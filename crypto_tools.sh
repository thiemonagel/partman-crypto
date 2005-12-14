#!/bin/sh

. /usr/share/debconf/confmodule

swap_is_safe () {
    local swap ret
    local IFS="
"
    ret=0
    for swap in $(cat /proc/swaps); do
       case $swap in
         Filename*) ;;      # header
         /dev/loop*) ;;     # OK
         /dev/mapper/*) ;;  # XX could be LVM2 ?
         *) ret=1 ;;	    # probably not OK
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

    log-output -t partman-crypto /sbin/losetup-aes -e $cipher $opts -p0 $loop $device -G / < $pass
    if [ $? -ne 0 ] ; then
        log "losetup failed"
        return 2
    fi

    return 0
}

setup_dmcrypt () {
    : TODO
}

setup_luks () {
    : TODO
}

setup_cryptdev () {
    local type realdev cipher keytype cryptdev
    type=$1
    realdev=$2
    cipher=$3
    keytype=$4

    case $type in
        dm-crypt)
          # TODO: crypt_name ?
          cryptdev=/dev/mapper/XXX
          setup_dmcrypt $cryptdev $realdev $cipher || return 1
          ;;

        dm-crypt-luks)
          # TODO: crypt_name ?
          cryptdev=/dev/mapper/ZZZ
          setup_luks $cryptdev $realdev $cipher || return 1
          ;;
      
        loop-AES)
          cryptdev=$(get_free_loop);
          [ -z "$cryptdev" ] && return 1

          case $keytype in
            random)
              keyfile=""
              ;;
            keyfile)
              keyfile=$(cat $id/keyfile)
              ;;
          esac

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

dev_erase () {
    local device size loop
    device=$1
    size=$2
    loop=$(get_free_loop)
    ret=1

    template="partman-crypto/warn_erase"
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

