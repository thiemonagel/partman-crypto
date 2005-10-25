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

setup_crypt_device () {
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

