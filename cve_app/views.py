from datetime import datetime, date
from django.shortcuts import render
from rest_framework.decorators import api_view, APIView, authentication_classes, permission_classes
from rest_framework.response import Response
from .serialized import SignupSerializer, LoginSerializer, CveSerializer, SingleSerializer
from django.core.cache import cache
import random
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
import uuid
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
import requests
import json
from .models import CVEdetails, SingleCve

# Create your views here.


def api_url_by_keyword(keyword):
    return f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keyword}'


def api_url_by_id(ids):
    return f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={ids}'


def sending_mail(gmail, token):
    subject = "C-V-E Tracker Wants Your Profile Needs to be verified"
    message = f"Paste This OTP in Authentication Field {token}"
    sender = settings.EMAIL_HOST_USER
    reciptent = [gmail]
    send_mail(subject, message, sender, reciptent)


def generate_otp():
    otp = ""
    for i in range(6):
        otp += str(random.randint(0, 9))
    return otp


@api_view(['POST'])
def signup_here(request):
    try:
        data = request.data
        serial = SignupSerializer(data=data)
        if serial.is_valid():
            cache.set(str(data['gmail'])+"_data", {
                'name': data['name'],
                'gmail': data['gmail'],
                'password': data['password'],
                'conf_pass': data['conf_pass']
            }, 1200)
            otp = generate_otp()
            cache.set(data['gmail'], otp, 300)
            try:
                sending_mail(data['gmail'], otp)
            except Exception as e:
                pass
            return Response({
                's': 'congrats! now you have to verify your email',
                'g': data['gmail']
            })
        return Response({
            'e': serial.errors
        })
    except Exception as e:
        return Response({
            'e': 'Something went wrong please try again'
        })


@ api_view(['POST'])
def verify_email(request):
    try:
        data = request.data
        otp = str(data['otp'])
        gmail = data['gmail']
        if request.data['work'] == 'resender':
            if not cache.get(gmail):
                otp = generate_otp()
                cache.set(gmail, otp, 300)
                sending_mail(gmail, otp)
                return Response({
                    'e': "succesfully resended check your email for new otp now"
                })
            else:
                return Response({
                    'e': "you can resend otp after five minutes only"
                })
        glob_data = cache.get(f"{gmail}_data")
        if glob_data:
            if otp == "" or len(otp) != 6 or not otp.isdigit():
                return Response({
                    'e': "please enter a valid otp here"
                })
            if gmail == "":
                return Response({
                    'e': "you are not identified please re-signup again"
                })
            otp_cache = cache.get(gmail)
            if otp_cache == None:
                return Response({'e': 'your otp has expired please click on resend otp button'})
            else:
                if otp_cache != otp:
                    return Response({
                        'e': 'incorrect otp please try again'
                    })
            person = User.objects.create(username=uuid.uuid4(),
                                         first_name=glob_data['name'], email=glob_data['gmail'])
            person.set_password(glob_data['password'])
            person.save()
            cache.delete(f"{gmail}_data")
            return Response({
                's': 'verified successfully'
            })
        else:
            return Response({
                'e': "your session has expired please restart from signup page"
            })

    except Exception as e:
        print(e)
        return Response({
            'e': 'Something went wrong please try again'
        })


@api_view(['POST'])
def login(request):
    try:
        data = request.data
        serial = LoginSerializer(data=data)
        if serial.is_valid():
            user = User.objects.filter(email=data['gmail'])
            if len(user) == 0 or not user[0].check_password(data['password']):
                return Response({
                    'e': 'no user found with these cridentials'
                })
            else:
                luks = Token.objects.filter(user=user[0])
                if len(luks) == 0:
                    toks = Token.objects.create(user=user[0])
                    toks.save()
                    return Response({
                        's': 'yes',
                        'token': toks.key
                    })
                return Response({
                    's': 'yes',
                    'token': luks[0].key
                })
        else:
            print(":th")
            return Response({
                'e': serial.errors
            })
    except Exception as e:
        print("dasfdsf", e)
        return Response({
            'e': 'something went wrong please try again'
        })


class Home(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        dats = CveSerializer(CVEdetails.objects.filter(
            user=request.user), many=True)
        for i in dats.data:
            i['jsof'] = SingleSerializer(
                SingleCve.objects.get(cve=i['cve_id'])).data
        return Response({
            'gama': {
                'name': request.user.first_name,
                'email': request.user.email,
                'data': dats.data[::-1]
            }
        })

    def post(self, request):
        try:
            today = date.today()
            now = datetime.now()
            data = request.data

            if len(CVEdetails.objects.filter(cve_id=data['id'], user=request.user)) == 0:
                my_obj = CVEdetails.objects.create(cve_id=data['id'], user=request.user, date_c=today.strftime(
                    "%m/%d/%y"), time_c=now.strftime("%H:%M:%S"))
                my_obj.save()

            if len(SingleCve.objects.filter(cve=data['id'])) == 0:
                sin_cve = SingleCve.objects.create(
                    cve=data['id'], cve_data=json.dumps(data))
                sin_cve.save()
            return Response({
                's': "saved"
            })
        except Exception as e:
            return Response({
                'e': "something went wrong"
            })


@ api_view(['GET'])
@ authentication_classes([TokenAuthentication])
@ permission_classes([IsAuthenticated])
def cve_finder(request):
    try:
        data = request.GET['query']
        data_arr = str(data).split("-")
        if len(data_arr) == 1:
            req = requests.get(api_url_by_keyword(data)).content
            if len(json.loads(req)['vulnerabilities']) > 0:
                return Response({
                    'e': "no",
                    'data': req
                })
            else:
                return Response({
                    'e': "your CVE'S keyword is not valid or it does'nt exist"
                })
        if len(data_arr) == 3:
            if data_arr[0].lower() != 'cve':
                return Response({
                    'e': "your CVE-Id is not valid"
                })
            if not data_arr[1].isdigit() or not data_arr[2].isdigit():
                return Response({
                    'e': "your CVE-Id is not valid"
                })
            req = requests.get(api_url_by_id(str(data).upper())).content
            if len(json.loads(req)['vulnerabilities']) > 0:
                return Response({
                    'e': "no",
                    'data': req
                })
            else:
                return Response({
                    'e': "your CVE-Id is not valid or it does'nt exist"
                })

        else:
            return Response({
                'e': "your CVE-Id is not valid"
            })
    except Exception as e:
        return Response({
            'e': "Something went wrong please try again"
        })


@ api_view(['GET'])
@ authentication_classes([TokenAuthentication])
@ permission_classes([IsAuthenticated])
def logout(request):
    try:
        key_ref = Token.objects.get(key=request.auth)
        key_ref.delete()
        return Response({
            's': 'Logout successfull'
        })
    except Exception as e:
        return Response({
            'e': 'something went wrong try again by refreshing the page'
        })
