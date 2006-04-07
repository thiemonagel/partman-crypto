#!/bin/sh

. /usr/share/debconf/confmodule

CRYPT_TYPES="loop-AES dm-crypt luks"

dm_is_safe() {
    # Might be non-encrypted, e.g. LVM2
    local type

    if [ -x /sbin/dmsetup ]; then
        type=$(/sbin/dmsetup table $swap | head -1 | cut -d " " -f3)
        if [ $type = crypt ]; then
            return 0
        fi
    fi
    return 1
}

loop_is_safe() {
    # TODO
    return 0
}

swap_is_safe () {
    local swap
    local ret=0
    local IFS="
"

    for swap in $(cat /proc/swaps); do
        case $swap in
            Filename*)
              # Header
              continue
              ;;
            /dev/loop*)
              if ! loop_is_safe $swap; then
                  ret=1
              fi
              ;;
            /dev/mapper/*)
              if ! dm_is_safe $swap; then
                  ret=1
              fi
              ;;
            *)
              # Presumably not OK
              ret=1
              ;;
        esac
    done

    return $ret
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
            echo /dev/loop/$n
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
    local loop device cipher keyfile opts pass
    loop=$1
    device=$2
    cipher=$3
    keyfile=$4

    [ -x /sbin/losetup-aes ] || return 1

    if [ $keyfile ]; then
        opts="-K $keyfile"
        pass="$keyfile.pass"
    else
        # random key
        opts="-H random"
        pass="/dev/null"
    fi

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
    /sbin/cryptsetup -c $cipher-$iv -h $hash -s $size create $mapping $device < $pass
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
    local type realdev cipher keytype cryptdev
    type=$1
    realdev=$2
    cipher=$3
    keytype=$4

    for opt in "keyfile ivalgorithm keyhash keysize"; do
        eval local $opt
        
        if [ -r "$id/$opt" ]; then
            eval $opt=$(cat $id/$opt)
        else
            eval $opt=""
        fi
    done

    case $type in
        dm-crypt)
          cryptdev=$(get_free_mapping)
          if [ -z "$cryptdev" ]; then
              return 1
          fi
          setup_dmcrypt $cryptdev $realdev $cipher $iv $hash $size $pass || return 1
          cryptdev="/dev/mapper/$cryptdev"
          ;;

        luks)
          cryptdev=$(get_free_mapping)
          if [ -z "$cryptdev" ]; then
              return 1
          fi
          setup_luks $cryptdev $realdev $cipher $iv $size $pass || return 1
          cryptdev="/dev/mapper/$cryptdev"
          ;;
      
        loop-AES)
          cryptdev=$(get_free_loop);
          if [ -z "$cryptdev" ]; then
              return 1
          fi
          if [ $keytype = random ]; then
              keyfile=""
          fi
          setup_loopaes $cryptdev $realdev $cipher $keyfile || return 1
          ;;

    esac

    echo $cryptdev > $dev/$id/crypt_active
    return 0
}

blocksize=$((8192*1024))

# NOTE: The copy can leave up to 4095 bytes at the end of the 
# partition not copied/overwritten. This is bad, but seems 
# tolerable because the steps shown in loop-AES documentation 
# for erasing data have the same problem.
    
dd_progresspipe () {
    local n in out
    in=$1
    out=$2
    size=$3
    blocks4k=$(($size/4096))
    n=0
    
    while dd if=$in bs=$blocksize count=1 2>/dev/null; do
      n=$((n+1))
      echo $n >&2
    done |
      log-output -t partman-crypto dd of=$out bs=4096 count=$blocks4k conv=notrunc

    # The below is an attempt to work around the problem by writing 
    # the remainder with bs=1. Unfortunately that doesn't work for 
    # partitions > 4GB because busybox dd skip=/seek= option values
    # are limited to ULONG_MAX.
    #
    #ret=$?
    #if [ $ret -eq 0 ]; then
    #    remaining=$(($size % 4096))
    #    if [ $remaining -gt 0 ]; then
    #        log-output -t partman-crypto dd if=$in of=$out skip=$written seek=$written bs=1 count=$remaining conv=notrunc
    #        ret=$?
    #    fi
    #fi
    # return $ret

    return $?
}

dd_show_progressbar () {
    local template in out size x
    template=$1
    in=$2
    out=$3
    size=$4
    blocks=$(($size/$blocksize))

    fifo=/tmp/erase_progress
    mknod $fifo p
    
    db_progress START 0 $blocks $template
    dd_progresspipe $in $out $size > $fifo 2>&1 &
    ddpid=$!

    while read x < $fifo; do
        db_progress STEP 1
    done

    rm $fifo
    db_progress STOP
    wait $ddpid
    return $?
}

dev_erase_data () {
    local device size loop
    device=$1
    size=$2
    loop=$(get_free_loop)
    ret=1

    template="partman-crypto/warn_erase"
    db_set $template false
    db_subst $template DEVICE $(humandev $device)
    db_input critical $template || true
    db_go || return
    db_get $template
        
    if [ "$RET" != true ]; then
        return 0
    fi

    if setup_loopaes $loop $device AES128 ""; then
        template="partman-crypto/progress/erase"
        db_subst $template DEVICE $(humandev $device)
        if dd_show_progressbar $template /dev/zero $loop $size; then
            ret=0
	fi
    fi
    
    if [ $ret -ne 0 ]; then
        template="partman-crypto/erase_failed"
        db_subst $template DEVICE $(humandev $device)
        db_input critical $template || true
        db_go
    fi

    log-output -t partman-crypto /sbin/losetup-aes -d $loop

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
    else
        db_metaget partman-basicfilesystems/text/no_mountpoint description
        value="$RET" # "none"
    fi

    db_metaget partman-crypto/text/specify_$option description
    RET=$(stralign -25 "$RET")
    printf "$option\t%s%s\n" "$RET" "$value"
}

crypto_dooption () {
    local part type cipher option altfile alternatives template

    part=$1
    type=$2
    cipher=$3
    option=$4

    if [ -f /lib/partman/ciphers/$type/$cipher/$option ]; then
        altfile="/lib/partman/ciphers/$type/$cipher/$option"
    else
        altfile="/lib/partman/ciphers/$type/$option"
    fi

    alternatives=""
    for i in $(cat $altfile); do
        if [ "$alternatives" ]; then
            alternatives="$alternatives, $i"
        else
            alternatives="$i"
        fi
    done

    template="partman-crypto/$option"
    db_subst $template choices $alternatives
    db_input critical $template || true
    db_go || exit 0
    db_get $template

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
                continue;
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
