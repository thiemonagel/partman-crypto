. /lib/partman/definitions.sh

dm_dev_is_safe() {
	local maj min dminfo deps
	maj="$1"
	min="$2"

	# First try the device itself
	dminfo=$(dmsetup table -j$maj -m$min 2> /dev/null | head -n1 | cut -d' ' -f3) || return 1
	if [ "$dminfo" = crypt ]; then
		return 0
	fi

	# Then check its deps instead
	deps=$(dmsetup deps -j "$maj" -m "$min" 2> /dev/null) || return 1
	deps=$(echo "$deps" | sed -e 's/.*://;s/[ (]//g;s/)/ /g')

	# deps is now a list like 3,2 3,1
	for dep in $deps; do
		maj=${dep%%,*}
		min=${dep##*,}
		dm_dev_is_safe "$maj" "$min" || return 1
	done

	return 0
}

dm_is_safe() {
	# Might be non-encrypted, e.g. LVM2
	local dminfo major minor
	type dmsetup > /dev/null 2>&1 || return 1

	dminfo=$(dmsetup info -c "$1" | tail -1) || return 1
	major=$(echo "$dminfo" | sed 's/ \+/ /g' | cut -d' ' -f2)
	minor=$(echo "$dminfo" | sed 's/ \+/ /g' | cut -d' ' -f3)

	dm_dev_is_safe "$major" "$minor" || return 1
	return 0
}

loop_is_safe() {
	local opts
	type losetup-aes > /dev/null 2>&1 || return 1

	opts=$(losetup-aes $1 2>&1)
	if [ $? -eq 0 ] && echo "$opts" | grep -q encryption=; then
		# loop entry has an encryption= option, assume it's safe
		return 0
	fi

	return 1
}

swap_is_safe () {
	local swap
	local IFS="
"

	for swap in $(cat /proc/swaps); do
		case $swap in
		Filename*)
			continue
			;;
		/dev/loop*)
			loop_is_safe ${swap%% *} || return 1
			;;
		/dev/mapper/*)
			dm_is_safe ${swap%% *} || return 1
			;;
		*)
			# Presume not safe
			return 1
			;;
		esac
	done

	return 0
}

get_free_loop () {
	O=$IFS
	IFS="
"
	for n in $(losetup-aes -a); do
		n=${n%%:*}
		n=${n#/dev/loop}
		n=${n#/}
		eval loop$n=1
	done
	IFS=$O

	for n in 0 1 2 3 4 5 6 7; do
		if eval [ -z "\$loop$n" ]; then
			if [ -d /dev/loop ]; then
				echo /dev/loop/$n
			else
				echo /dev/loop$n
			fi
			break
		fi
	done
}

get_free_mapping() {
	for n in 0 1 2 3 4 5 6 7; do
		if [ ! -b "/dev/mapper/crypt$n" ]; then
			echo "crypt$n"
			break
		fi
	done
}

setup_loopaes () {
	local loop device cipher keytype keyfile opts pass
	loop=$1
	device=$2
	cipher=$3
	keytype=$4
	keyfile=$5

	[ -x /sbin/losetup-aes ] || return 1

	case $keytype in
	keyfile)
		opts="-K $keyfile"
		pass="$keyfile.pass"
		;;
	random)
		opts="-H random"
		pass="/dev/null"
		;;
	esac

	log-output -t partman-crypto \
	/sbin/losetup-aes -e $cipher $opts -p0 -G / $loop $device < $pass
	if [ $? -ne 0 ] ; then
		log "losetup failed"
		return 2
	fi

	return 0
}

setup_dmcrypt () {
	local mapping device cipher iv hash size pass
	mapping=$1
	device=$2
	cipher=$3
	iv=$4
	hash=$5
	size=$6
	pass=$7

	[ -x /sbin/cryptsetup ] || return 1

	log-output -t partman-crypto \
	/sbin/cryptsetup -c $cipher-$iv -d $pass -h $hash -s $size create $mapping $device
	if [ $? -ne 0 ] ; then
		log "cryptsetup failed"
		return 2
	fi

	return 0
}

setup_luks () {
	local mapping device cipher iv size pass
	mapping=$1
	device=$2
	cipher=$3
	iv=$4
	size=$5
	pass=$6

	[ -x /sbin/cryptsetup ] || return 1

	log-output -t partman-crypto \
	/sbin/cryptsetup -c $cipher-$iv -s $size luksFormat $device $pass
	if [ $? -ne 0 ] ; then
		log "luksFormat failed"
		return 2
	fi

	log-output -t partman-crypto \
	/sbin/cryptsetup -d $pass luksOpen $device $mapping
	if [ $? -ne 0 ] ; then
		log "luksOpen failed"
		return 2
	fi

	return 0
}

setup_cryptdev () {
	local type id realdev cryptdev
	type=$1
	id=$2
	realdev=$3

	for opt in keytype cipher keyfile ivalgorithm keyhash keysize; do
		eval local $opt
		
		if [ -r "$id/$opt" ]; then
			eval $opt=$(cat $id/$opt)
		else
			eval $opt=""
		fi
	done

	case $type in
	dm-crypt)
		cryptdev=$(mapdevfs $realdev)
		cryptdev="${cryptdev##*/}_crypt"
		if [ -b "/dev/mapper/$cryptdev" ]; then
			cryptdev=$(get_free_mapping)
			if [ -z "$cryptdev" ]; then
				return 1
			fi
		fi
		if [ $keytype = passphrase ]; then
			setup_luks $cryptdev $realdev $cipher $ivalgorithm $keysize $keyfile || return 1
		elif [ $keytype = random ]; then
			setup_dmcrypt $cryptdev $realdev $cipher $ivalgorithm plain $keysize $keyfile || return 1
		else
			setup_dmcrypt $cryptdev $realdev $cipher $ivalgorithm $keyhash $keysize $keyfile || return 1
		fi
		cryptdev="/dev/mapper/$cryptdev"
		;;

	loop-AES)
		cryptdev=$(get_free_loop);
		if [ -z "$cryptdev" ]; then
			return 1
		fi
		setup_loopaes $cryptdev $realdev $cipher $keytype $keyfile || return 1
		;;

	esac

	echo $cryptdev > $id/crypt_active
	db_subst partman-crypto/text/in_use DEV "${cryptdev##*/}"
	db_metaget partman-crypto/text/in_use description
	partman_lock_unit $(mapdevfs $realdev) "$RET"
	return 0
}

wipe () {
	local template dev fifo pid x
	template=$1
	dev=$2
	fifo=/var/run/wipe_progress

	mknod $fifo p
	/bin/blockdev-wipe -s 65536 $dev > $fifo &
	pid=$!

	db_progress START 0 100 $template
	while read x <&9; do
		db_progress STEP 1
	done 9< $fifo
	db_progress STOP

	rm $fifo
	wait $pid
	return $?
}

dev_wipe () {
	local device size method interactive targetdevice
	device=$1
	size=$2
	method=$3
	interactive=$4
	if [ "$interactive" != "no" ]; then
		interactive="yes"
	fi
	ret=1

	if [ $interactive = yes ]; then
		# Confirm before erasing
		template="partman-crypto/warn_erase"
		db_set $template false
		db_subst $template DEVICE $(humandev $device)
		db_input critical $template || true
		db_go || return
		db_get $template
		if [ "$RET" != true ]; then
			return 0
		fi
	fi

	# Setup crypto
	if [ $method = loop-AES ]; then
		targetdevice=$(get_free_loop)
		setup_loopaes $targetdevice $device AES128 random || return 1
	elif [ $method = dm-crypt ]; then
		targetdevice=$(get_free_mapping)
		setup_dmcrypt $targetdevice $device aes cbc-essiv:sha256 plain 128 /dev/urandom || return 1
		targetdevice="/dev/mapper/$targetdevice"
	else
		# Just wipe the device with zeroes
		targetdevice=$device
	fi

	# Erase
	template="partman-crypto/progress/erase"
	db_subst $template DEVICE $(humandev $device)
	if ! wipe $template $targetdevice; then
		template="partman-crypto/erase_failed"
		db_subst $template DEVICE $(humandev $device)
		db_input critical $template || true
		db_go
	else
		ret=0
	fi

	# Teardown crypto
	if [ $method = loop-AES ]; then
		log-output -t partman-crypto /sbin/losetup-aes -d $targetdevice
	elif [ $method = dm-crypt ]; then
		log-output -t partman-crypto /sbin/cryptsetup remove ${targetdevice##/dev/mapper/}
	fi

	return $ret
}

crypto_dochoice () {
	local part type cipher option value

	part=$1
	type=$2
	cipher=$3
	option=$4

	if [ ! -f /lib/partman/ciphers/$type/$cipher/$option ] && \
	   [ ! -f /lib/partman/ciphers/$type/$option ]; then
		exit 0
	fi

	if [ -f $part/$option ]; then
		value=$(cat $part/$option)
		template="partman-crypto/text/$option/$value"
		db_metaget $template description && value="$RET"
	else
		value="none"
		template=partman-basicfilesystems/text/no_mountpoint
		db_metaget $template description && value="$RET"
	fi

	db_metaget partman-crypto/text/specify_$option description
	RET=$(stralign -25 "$RET")
	printf "%s\t%s%s\n" "$option" "$RET" "$value"
}

crypto_dooption () {
	local part type cipher option choices altfile template

	part=$1
	type=$2
	cipher=$3
	option=$4

	if [ -f /lib/partman/ciphers/$type/$cipher/$option ]; then
		altfile="/lib/partman/ciphers/$type/$cipher/$option"
	else
		altfile="/lib/partman/ciphers/$type/$option"
	fi

	choices=$(
		for value in $(cat $altfile); do
			description="$value"
			template="partman-crypto/text/$option/$value"
			db_metaget $template description && description="$RET"
			printf "%s\t%s\n" $value "$description"
		done
	)

	template="partman-crypto/$option"
	debconf_select critical $template "$choices" "" || exit 0
	if [ "$RET" = none ]; then
		rm -f $part/$option
		return
	fi

	echo $RET > $part/$option
}

# Loads all modules for a given crypto type and cipher
crypto_load_modules() {
	local type cipher moduledir modulefile module
	type=$1
	cipher=$2
	moduledir=/var/run/partman-crypto/modules

	if [ ! -d $moduledir ]; then
		mkdir -p $moduledir
	fi

	for modulefile in \
	  /lib/partman/ciphers/$type/module \
	  /lib/partman/ciphers/$type/$cipher/module; do
		[ -f $modulefile ] || continue
		for module in $(cat $modulefile); do
			if [ -f $moduledir/$module ]; then
				# Already loaded
				continue
			fi
	
			if modprobe -q $module; then
				touch $moduledir/$module
			else
				rm -f $moduledir/$module
				return 1
			fi
		done
	done

	return 0
}

# Checks that we have sufficient memory to load crypto udebs
crypto_check_mem() {
	local verbose="$1"
	local memfree

	if [ ! -e /proc/meminfo ]; then
		return 0
	fi

	memfree=$(grep MemFree /proc/meminfo | head -1 | \
		  sed 's/.*:[[:space:]]*\([0-9]*\).*/\1/')
	# A more or less arbitrary limit
	if [ "$memfree" -lt 10000 ]; then
		if [ "$verbose" != "true" ]; then
			return 1
		fi

		db_set partman-crypto/install_udebs_low_mem false
		db_fset partman-crypto/install_udebs_low_mem seen false
		db_input critical partman-crypto/install_udebs_low_mem
		db_go || true
		db_get partman-crypto/install_udebs_low_mem
		if [ "$RET" != true ]; then
			return 1
		fi
	fi

	return 0
}

# Loads additional crypto udebs
crypto_load_udebs() {
	local packages udebdir package memfree
	packages="$1"
	udebdir=/var/run/partman-crypto/udebs

	if [ -z "$packages" ]; then
		return 0
	fi

	if [ ! -d $udebdir ]; then
		mkdir -p $udebdir
	fi

	for package in $packages; do
		if [ -f $udebdir/$package ]; then
			continue
		fi

		crypto_check_mem "true" || return 1

		if ! anna-install $package; then
			db_fset partman-crypto/install_udebs_failure seen false
			db_input critical partman-crypto/install_udebs_failure
			db_go || true
			return 1
		fi

		touch $udebdir/$package
	done

	# The udeb installation run usually adds new kernel modules
	if [ -x /sbin/depmod ]; then
		depmod -a > /dev/null 2>&1 || true
	fi

	return 0
}

# Sets the defaults for a given crypto type
crypto_set_defaults () {
	local part type
	part=$1
	type=$2

	[ -d $part ] || return 1

	case $type in
	dm-crypt)
		echo aes > $part/cipher
		echo 256 > $part/keysize
		echo cbc-essiv:sha256 > $part/ivalgorithm
		echo passphrase > $part/keytype
		echo sha256 > $part/keyhash
		;;
	loop-AES)
		echo AES256 > $part/cipher
		echo keyfile > $part/keytype
		rm -f $part/keysize
		rm -f $part/ivalgorithm
		rm -f $part/keyhash
		;;
	esac
	return 0
}

# Does initial setup for a crypto method
crypto_prepare_method () {
	local part type package
	part=$1
	type=$2
	package=''

	[ -d $part ] || return 1
	case $type in
	dm-crypt)
		package="partman-crypto-dm"
		;;
	loop-AES)
		package="partman-crypto-loop"
		;;
	*)
		return 1
		;;
	esac

	# 1A - Pull in the method package and additional dependencies
	crypto_load_udebs $package || return 1

	# 1B - Verify that it worked
	crypto_check_required_tools $type || return 1

	# 2 - Set the defaults for the chosen type
	crypto_set_defaults $part $type || return 1

	# 3 - Also load the kernel modules needed for the chosen type/cipher
	[ -f $part/cipher ] || return 1
	crypto_load_modules $type $(cat $part/cipher) || return 1

	return 0
}

crypto_check_required_tools() {
	local tools

	tools="blockdev-keygen"
	case $1 in
	dm-crypt)
		tools="$tools dmsetup cryptsetup"
		;;
	loop-AES)
		tools="$tools gpg base64"
		;;
	*)
		return 1
	esac

	for tool in $tools; do
		if ! type $tool > /dev/null 2>&1 ; then
			db_fset partman-crypto/tools_missing seen false
			db_input critical partman-crypto/tools_missing
			db_go || true
			return 1
		fi
	done
	return 0
}

crypto_check_required_options() {
	local id type list options
	path=$1
	type=$2

	case $type in
	dm-crypt)
		options="cipher keytype keyhash ivalgorithm keysize"
		;;
	loop-AES)
		options="cipher keytype"
		;;
	esac

	list=""
	for opt in $options; do
		[ -f $path/$opt ] && continue
		db_metaget partman-crypto/text/specify_$opt description || RET="$opt:"
		desc=$RET
		db_metaget partman-crypto/text/missing description || RET="missing"
		value=$RET
		if [ "$list" ]; then
			list="$list
$desc $value"
		else
			list="$desc $value"
		fi
	done

	# If list is non-empty, at least one option is missing
	if [ ! -z "$list" ]; then
		templ="partman-crypto/options_missing"
		db_fset $templ seen false
		db_subst $templ DEVICE "$(humandev $path)"
		db_subst $templ ITEMS "$list"
		db_input critical $templ
		db_go || true
		return 1
	fi
	return 0
}

crypto_check_setup() {
	crypt=
	for dev in $DEVICES/*; do
		[ -d "$dev" ] || continue
		cd $dev

		partitions=
		open_dialog PARTITIONS
		while { read_line num id size type fs path name; [ "$id" ]; }; do
			[ "$fs" != free ] || continue
			partitions="$partitions $id,$num,$path"
		done
		close_dialog

		for p in $partitions; do
			set -- $(IFS=, && echo $p)
			id=$1
			num=$2
			path=$3

			[ -f $id/method ] || continue
			[ -f $id/crypto_type ] || continue

			method=$(cat $id/method)
			if [ $method != crypto ]; then
				continue
			fi
			type=$(cat $id/crypto_type)
			crypt=yes

			crypto_check_required_tools $type
			crypto_check_required_options "$dev/$id" $type
		done
	done

	if [ -z "$crypt" ]; then
		db_fset partman-crypto/nothing_to_setup seen false
		db_input critical partman-crypto/nothing_to_setup
		db_go || true
		return 1
	fi
	return 0
}

crypto_setup() {
	local interactive s dev id size path methods partitions type keytype keysize
	interactive=$1
	if [ "$interactive" != "no" ]; then
		interactive="yes"
	fi

	# Commit the changes
	for s in /lib/partman/commit.d/*; do
	    if [ -x $s ]; then
		$s || {
		    db_input high partman-crypto/commit_failed || true
		    db_go || true
		    for s in /lib/partman/init.d/*; do
			if [ -x $s ]; then
			    $s || return 255
			fi
		    done
		    return 0
		}
	    fi
	done

	if ! swap_is_safe; then
		db_fset partman-crypto/unsafe_swap seen false
		db_input critical partman-crypto/unsafe_swap
		db_go || true
		return 1
	fi

	# Erase crypto-backing partitions
	for dev in $DEVICES/*; do
		[ -d "$dev" ] || continue
		cd $dev

		partitions=
		open_dialog PARTITIONS
		while { read_line num id size type fs path name; [ "$id" ]; }; do
			[ "$fs" != free ] || continue
			partitions="$partitions $id,$size,$path"
		done
		close_dialog
		
		for part in $partitions; do
			set -- $(IFS=, && echo $part)
			id=$1
			size=$2
			path=$3

			[ -f $id/method ] || continue
			method=$(cat $id/method)
			if [ $method != crypto ]; then
				continue
			fi

			if [ -f $id/crypt_active ] || [ -f $id/skip_erase ]; then
				continue
			fi

			if ! dev_wipe $path $size $(cat $id/crypto_type) $interactive; then
				db_fset partman-crypto/commit_failed seen false
				db_input critical partman-crypto/commit_failed
				db_go || true
				return 1
			fi
		done
	done

	# Create keys and do losetup/dmsetup
	for dev in $DEVICES/*; do
		[ -d "$dev" ] || continue
		cd $dev

		partitions=
		open_dialog PARTITIONS
		while { read_line num id size type fs path name; [ "$id" ]; }; do
			[ "$fs" != free ] || continue
			partitions="$partitions $id,$num,$path"
		done
		close_dialog
		
		for part in $partitions; do
			set -- $(IFS=, && echo $part)
			id=$1
			num=$2
			path=$3

			[ -f $id/method ] || continue
			[ -f $id/crypto_type ] || continue
			[ -f $id/cipher ] || continue
			[ -f $id/keytype ] || continue

			method=$(cat $id/method)
			if [ $method != crypto ]; then
				continue
			fi

			type=$(cat $id/crypto_type)
			keytype=$(cat $id/keytype)
			cipher=$(cat $id/cipher)

			# Cryptsetup uses create_keyfile for all keytypes
			if [ $keytype = keyfile ] || [ $type != loop-AES ]; then
				keyfile=$(mapdevfs $path | tr / _)
				keyfile="$dev/$id/${keyfile#_dev_}"
				if [ $type = loop-AES ]; then
					keyfile="${keyfile}.gpg"
				fi

				if [ ! -f $keyfile ]; then
					if [ $type != loop-AES ]; then
						keysize=""
						[ -f $id/keysize ] && keysize=$(cat $id/keysize)
						/bin/blockdev-keygen "$(humandev $path)" $keytype "$keyfile" $keysize
					else
						/bin/blockdev-keygen "$(humandev $path)" $keytype "$keyfile"
					fi
					if [ $? -ne 0 ]; then
						db_fset partman-crypto/commit_failed seen false
						db_input critical partman-crypto/commit_failed
						db_go || true
						failed=1
						break
					fi
				fi

				echo $keyfile > $id/keyfile
			fi

			if [ ! -f $id/crypt_active ]; then
				log "setting up encrypted device for $path"

				if ! setup_cryptdev $type $id $path; then
					db_fset partman-crypto/commit_failed seen false
					db_input critical partman-crypto/commit_failed
					db_go || true
					failed=1
					break
				fi
			fi
		done
	done

	if [ $failed ]; then
		return 1
	fi

	stop_parted_server

	restart_partman
	return 0
}
