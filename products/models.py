from django.db import models
from baseapp.models import BaseModel

class Product(BaseModel):
    title=models.CharField(max_length=225)
    description=models.TextField(blank=True)
    price= models.DecimalField(max_digits=10, decimal_places=2)
    stock=models.PositiveIntegerField(default=0)
    is_active=models.BooleanField(default=True)

    def __str__(self):
        return self.title  