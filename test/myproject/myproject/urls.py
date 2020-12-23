from django.conf.urls import url
from django.contrib import admin

from blog.views import * # views.py에서 우리가 만든 helloworld 함수를 가져온다.

from map.views import regionjson
from baguni.views import comment_write_view, post_delete
from django.urls import path, include

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    #url(r'^$', index),  # url 객체를 만들어준다.
    url(r'^default/', default),

    url(r'^link$', link),
    
    # 로그 익스플로러 관련 페이지
    url(r'^logs$', logExplorer),
    url(r'^viewer$', Viewer),

    # 로그 바구니 관련 페이지
    
    url(r'^logbaguni$', comment_write_view),
    
    # 자동화 쿼리 관련 페이지
    url(r'^query$', QueryMain),
    url(r'^query/(?P<id>\d+)/', Query),
    #url(r'^ip/(?P<slug>[-\w]+)/', ip_query),
    path('ip/<str:id>/', ip_query),
    path('iamkey/<str:id>/', iamkey_query),



    # map
    path('', include('map.urls')),

    # query
    #path('query/', include('query.urls')),


    
    #baguni
    path('baguni/', include('baguni.urls')),
    url(r'^logbaguni$', comment_write_view),
    url(r'^postdelete$', post_delete),

    #regist
    path('regist/', include('regist.urls')),

    path('check/', include('check.urls')),


    # Background DB
    #path('background/<int:id>/',background),
    url(r'^background/(?P<id>\d+)', background),
    
]