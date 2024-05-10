obj-m += pe-sim.o

pe-sim-objs			+= main.o
pe-sim-objs			+= fifo.o
pe-sim-objs			+= ipc.o
pe-sim-objs			+= eth.o
pe-sim-objs			+= pe/pe.o
pe-sim-objs			+= pe/stadb.o
pe-sim-objs			+= pe/pkt.o
pe-sim-objs			+= pe/BQM.o
pe-sim-objs			+= pe/cmd_proc.o
pe-sim-objs			+= pe/tx.o
pe-sim-objs			+= pe/rx.o
pe-sim-objs			+= pe/ba.o
pe-sim-objs			+= pe/dbg.o

ccflags-y += -O2 -funroll-loops -D__CHECK_ENDIAN__ -I$(PWD) -I$(PWD)/pe -I$(PWD)/pe/incl

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	rm -f *.a *.s *.ko *.ko.cmd *.mod.* .pe-sim.* modules.order Module.symvers buildlog.txt
	rm -rf .tmp_versions
	find . -name ".*.o.cmd" -exec rm -f {} \;
	find . -name "*.o" -exec rm -f {} \;
