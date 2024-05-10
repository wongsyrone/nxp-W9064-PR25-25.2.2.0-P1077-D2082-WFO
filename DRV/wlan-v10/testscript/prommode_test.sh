insmod ap8x-v10.ko
sleep 1
iwpriv wdev0 setcmd "bpei"
sleep 1
iwpriv wdev0 setcmd "debug addsta 005043200304 2 0"
sleep 1
iwpriv wdev0 setcmd "debug addbss"
sleep 1
iwpriv wdev0 setcmd "setreg addr0 0x410"
sleep 1
iwpriv wdev0 setcmd "setreg addr0 0x414"
sleep 1
iwpriv wdev0 setcmd "setreg addr0 0x418"

# Enable message for rx-desc / rx-payload
iwpriv wdev0 setcmd "pktmsg 0xc"

# Set rx-qid = 8
iwpriv wdev0 setcmd "rxq 8"

# Run the loopback test
i=1
max=100
if [ $# -gt 0 ]; then
	max=$1
fi

while [ 1 ]
do
if [ $i -gt $max ]; then
        break;
fi

	echo run $i th times ================
	#sleep 1

	iwpriv wdev0 setcmd "loopback 1 1 8"

	
i=$((i+1))
done

