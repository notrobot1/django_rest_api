from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    SHIRT_SIZES = (
        ('M', 'Мужчина'),
        ('F', 'Женщина'),
        ('N', 'Не указанно'),

    )
    SHIRT_SIZES1 = (
        ('a', 'Не женат'),
        ('b', 'Женат'),
        ('c', 'В активном поиске'),
        ('d', 'Все сложно'),
        ('q', 'Не указано'),
    )
    birth_date = models.DateField(null=True, blank=True)
    gender = models.CharField("M - мужчина ; F - женщина ; N - не указано", max_length=1, choices=SHIRT_SIZES, default="N")
    country = models.CharField("Страна", null=True, blank=True, max_length=30, default='')
    city = models.CharField("Город",null=True, blank=True,max_length=30, default='')
    family_status = models.CharField("Семейное положение: a - Не женат; b - женат; с - в активном поиске; d - все сложно; q - не указано;",max_length=1, choices=SHIRT_SIZES1, default="q")
# Create your models here.
