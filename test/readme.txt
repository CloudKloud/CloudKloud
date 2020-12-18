# 구성 (중요 파일만 설명)

|- myproject ( 전체 django application)
    |- blog (앱 폴더 - 김도훈 구현중)
        |- views.py (urls.py 통해 특정 주소 접속시 views.py의 함수를 호출하고, 함수에서는 어떤 html파일 보여줄지 설정)
    
    |- map (앱 폴더 - 유예린 구현중)
        |- 앱끼리는 구성 같음

    |- myproject (웹사이트의 핵심 설정 정보등을 담은 폴더)
        |- settings.py (웹사이트의 여러 설정이 포함됨, 앱 추가시 내부의 INSTALLED_APPS 리스트에 추가 필요)
        |- urls.py (웹사이트의 페이지들을 연결해주는 패턴 목록이 포함된 파일, views.py의 어떤 함수를 호출할지 설정)
    
    |- static (css, fonts, images, js 등의 파일 담김)
    |- templates (각 앱에서 사용하는 html 파일 담김)
        |- Default.html (기본 템플릿)
        
    |- manage.py ("manage.py runserver" 커맨드 통해 django 앱 실행 가능)

|- readme.md (구성도 설명)

