from models.hr_user import HR1User, HR2User, HR3User, HR4User
from models.ct_users import CT1User, CT2User, CT3User
from models.log_users import LOG1User, LOG2User
from models.fin_users import FIN1User, FIN2User, FIN3User, FIN4User, FIN5User

model_registry = {
    'hr1': HR1User,
    'hr2': HR2User,
    'hr3': HR3User,
    'hr4': HR4User,
    'ct1': CT1User,
    'ct2': CT2User,
    'ct3': CT3User,
    'log1': LOG1User,
    'log2': LOG2User,
    'fin1': FIN1User,
    'fin2': FIN2User,
    'fin3': FIN3User,
    'fin4': FIN4User,
    'fin5': FIN5User,
}
