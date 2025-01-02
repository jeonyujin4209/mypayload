# Improper Session Management

WEB에서 특정 샌드박스 환경을 가진 기능에서  
환경 탈출 시 GUI 내 세션이 끊어지는 경우가 있었으나  
프론트엔드에서만 끊길 뿐 실제로는 연결이 유지되어  
Burpsuite 내 Reapeter를 사용해 탈출된 환경에서 자유롭게 명령어 사용 가능했음.

