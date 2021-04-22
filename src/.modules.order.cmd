cmd_/home/adl/experiment/src/modules.order := {   echo /home/adl/experiment/src/get_sys_call_table.ko; :; } | awk '!x[$$0]++' - > /home/adl/experiment/src/modules.order
