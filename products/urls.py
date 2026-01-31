
from .views import ProductViewSet
from rest_framework import routers

router=routers.SimpleRouter()
router.register(r'products',ProductViewSet,basename='product')
urlpatterns=router.urls