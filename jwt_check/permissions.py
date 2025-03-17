
PAGE_MAPPING = {
    '/registration': 'SDRG',
    '/sample/test': 'SDST',
    '/sample/results': 'SDSR',
    '/reports/summary': 'SDRS',
}

PAGE_ACTION_MAPPING = {
    'SDRS': {
        'POST':'R',
    },
}

GEN_ACTION_MAPPING = {
    'POST': 'RW',
    'PUT': 'RW',
    'DELETE': 'RW',
    'GET': 'R',
}
