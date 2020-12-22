# Cloud?Kloud!


## About CK

cloud? Klooud!

CK는 클라우드 로그 분석 지원 솔루션 입니다.

이 서비스는 AWS의 EC2, S3, RDS, IAM를 지원합니다.

해당 서비스는 무료입니다.

해당  [주소](https://github.com/CloudKloud/CloudKloud)로 가면 code를 확인할 수 있고 서비스를 활용하기 위해 설정하는 절차를 안내 해줍니다.




## Main

### Region

여기에서는 Blacklist IP가 사용중인 리전을 세계지도를 통해서 확인할 수 있습니다.

이 [주소](https://rescure.me/index.html)에서 Blacklist IP 목록을 다운 받아서 사용할 수 있고, 직접 BlacklistIP.txt 파일을 편집하여 사용할 수도 있습니다.

![image](https://user-images.githubusercontent.com/54059519/102449815-6b934980-4078-11eb-9d30-4409ef930971.png)

### Threat Item tables

위험도를 기준으로 분류된 3가지의 테이블입니다.

각각의 테이블에서는 해당 위험도에 해당하는 항목들 중에서 가장 많이 검출된 목록 순으로 상위 5개 항목을 보여줍니다.

__details__ 버튼을 누르면 해당 위협항목에 대한 _Threat Items Detail Page_ 로 넘어가서 자세한 로그 내용을 볼 수 있습니다.

_이 사진들은 예시 입니다._

<img src="https://user-images.githubusercontent.com/54059519/102449889-8f568f80-4078-11eb-8b61-92c6958e3fdc.png" width="600" height="400"> 

<img src="https://user-images.githubusercontent.com/54059519/102449942-b3b26c00-4078-11eb-9dd9-a55af50a2652.png" width="600" height="400"> 

<img src="https://user-images.githubusercontent.com/54059519/102449957-bf059780-4078-11eb-88c2-8e193fd227a3.png" width="600" height="400"> 




## Log Explorer

Cloud Watch의 모든 로그를 볼 수 있습니다.

텍스트기반 검색 기능을 활용할 수 있습니다.

<img width="760" alt="LEnormal" src="https://user-images.githubusercontent.com/54059519/102466242-1cf2a900-4092-11eb-9b32-47cece1ed2ec.PNG">



## Threat Items

위협 항목들의 목록과 위험도를 함께 볼 수 있습니다.

__details__ 버튼을 누르면 해당 위협항목에 대한 _Threat ITtems Detail page_ 로 넘어가서 검출된 자세한 내용을 볼 수 있습니다.

<img width="518" alt="threatitem" src="https://user-images.githubusercontent.com/54059519/102468904-727c8500-4095-11eb-8d1a-b3597b9ae1f3.png">


### Detail Page

가이드라인을 기반으로 수집된 모든 Cloud Watch 로그를 볼 수 있습니다. 

첫번째로, 시간대비 로그의 양에 대한 그래프를 볼 수 있습니다.

__plus__ 버튼을 누르면 로그에 대한 더 자세한 정보를 볼 수 있습니다.

파이차트에서 특정 __IAM__ 이용자나 특정하고 싶은 __IP__ 를 클릭하면 해당 __IAM__ 이용자나 __IP__ 의 활동 내용을 따로 뽑아서 볼 수 있습니다.

또한, 여기서 나중에 다시 보고싶은 로그가 있다면 _log baguni_ 에 추가하여 이용자가 원할때 _log baguni_ 메뉴를 통해서 본인이 저장한 로그만 모아서 다시 확인할 수 있습니다.

<img width="722" alt="LE1" src="https://user-images.githubusercontent.com/54059519/102453895-7520af80-4080-11eb-8612-9e1b7c8bfb40.PNG">
<img width="735" alt="LE2" src="https://user-images.githubusercontent.com/54059519/102453912-7fdb4480-4080-11eb-913e-c2eb46ec52b1.PNG">
<img width="758" alt="LE3" src="https://user-images.githubusercontent.com/54059519/102453915-823d9e80-4080-11eb-96af-133b931f10d9.PNG">

#### * + 버튼을 눌렀을 때

<img width="755" alt="LE4" src="https://user-images.githubusercontent.com/54059519/102453929-849ff880-4080-11eb-93de-d7d58329716a.PNG">

카테고리를 기반으로한 추가적인 검색도 가능합니다.

<img width="804" alt="LEsearch" src="https://user-images.githubusercontent.com/54059519/102456836-24f81c00-4085-11eb-8c1e-887fa19489b2.PNG">

#### * 특정 IAM user를 클릭하였을 때
<img width="614" alt="LE5" src="https://user-images.githubusercontent.com/54059519/102453960-88cc1600-4080-11eb-8734-d728a0481e73.PNG">
<img width="299" alt="LE6" src="https://user-images.githubusercontent.com/54059519/102453963-89fd4300-4080-11eb-9f4b-756ae0be7d7a.PNG">
<img width="751" alt="LE7" src="https://user-images.githubusercontent.com/54059519/102453964-8a95d980-4080-11eb-81be-762c26f6343b.PNG">




## Log Baguni

이용자가 저장한 로그의 달력과 목록을 확인할 수 있습니다.

로그의 달력은 저장된 로그가 생성된 시점을 기준으로 표시됩니다.

목록 부분에서 _log baguni_ 에 저장된 로그를 삭제할 수 있습니다.

<img width="1200" alt="BaguniCalender2" src="https://user-images.githubusercontent.com/54059519/102459691-44914380-4089-11eb-9895-662feb2821c7.png">
<img width="1200" alt="LogBaguni" src="https://user-images.githubusercontent.com/54059519/102459799-6d193d80-4089-11eb-81b7-f553cf506e1e.png">

#### 달력은 월별이 아닌 주간별 일별로도 확인이 가능합니다.

<img width="1200" alt="BaguniWeek" src="https://user-images.githubusercontent.com/54059519/102459700-4955f780-4089-11eb-8198-a3e557030e9b.png">
<img width="1200" alt="BaguniDay" src="https://user-images.githubusercontent.com/54059519/102459745-57a41380-4089-11eb-8793-2466b7671661.png">


## Setting Check

현재 설정이 잘못되어있는 것이 있는지 확인할 수 있습니다.

잘못 설정된 항목이 있다면 __guideline__ 을 참고하여 곧바로 수정해야 안전성을 확보할 수 있습니다.

<img width="1200" alt="settingcheck" src="https://user-images.githubusercontent.com/76162371/102596271-46780700-415c-11eb-8d42-9b1a5276c199.png">


#### 영어 버전 링크
https://yelynew.github.io/CK/



