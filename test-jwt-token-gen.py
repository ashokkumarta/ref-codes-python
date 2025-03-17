from jwt_gen import jwt_gen
from jwt_check import jwt_check


if __name__ == '__main__':
    # Tests
    vals = {'aud':'emp001', 'email':'emp001@shanmuga.com', 'name':'Emp, 001', 'allowed-actions':['SDRGRW','SDABR','SDXYR'], 'allowed-data':['SD001']}
    token = jwt_gen.createJwt(vals)

    print(f'\nToken generated for {vals}')

    # Allowed access.. explicit
    try:
        print(f'\nAllowed access.. explicit scenario')
        userJson = jwt_check.checkAccess(token, 'SD001', '/registration', 'POST')
    except ValueError as e:
        print(f'Access not allowed. Reason: {e}\n')
    else:
        print(f'Access allowed\n')

    # Allowed access.. implied
    try:
        print(f'\nAllowed access.. implied scenario')
        userJson = jwt_check.checkAccess(token, 'SD001', '/registration', 'GET')
    except ValueError as e:
        print(f'Access not allowed. Reason: {e}')
    else:
        print(f'Access allowed\n')

    # Access denied.. 
    try:
        print(f'\nAllowed denied.. scenario')
        userJson = jwt_check.checkAccess(token, 'SD001', '/sample/results', 'POST')
    except ValueError as e:
        print(f'Access not allowed. Reason: {e}')
    else:
        print(f'Access allowed\n')



