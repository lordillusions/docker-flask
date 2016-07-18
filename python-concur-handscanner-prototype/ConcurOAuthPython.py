#!/usr/bin/python
# -*- coding: utf-8 -*-
import requests
import json
import base64
import urllib

from prettytable import PrettyTable
import operator

from concur import ConcurClient, ConcurAPIError

#baseUrl = 'https://www.concursolutions.com'
baseUrl = 'https://implementation.concursolutions.com'
oauthUrl = baseUrl + '/net2/oauth2/accesstoken.ashx'
reportDigestUrl = ''


def getbasic(user, password):
    # basic authentication (according to HTTP)

    return base64.encodestring(user + ':' + password)


def getTokenGivenUsernamePasswordAndConsumerKey(username, password,
                                                consumerKey):
    basic = 'Basic ' + getbasic(username, password)
    headers1 = {'Authorization': basic.rstrip(),
                'X-ConsumerKey': consumerKey,
                'Accept': 'application/json'}
    r = requests.get(oauthUrl, headers=headers1)
    return json.loads(r.content)


def test():
    loginID = 'wchaves2@br.ibm.com'

    access_token_full = \
        getTokenGivenUsernamePasswordAndConsumerKey(loginID, 'testtest1'
                                                    , '85Bvf1931AXmiNCfeB1O5L')
    print access_token_full
    if access_token_full.has_key('Error'):
        print 'Wrong Password'
    else:
        token = access_token_full['Access_Token']['Token']

        # concur = ConcurClient('85Bvf1931AXmiNCfeB1O5L','Lwq6xDnvWSN8YQHrw5WMYDyGa9I1FAxs',str(access_token['Access_Token']['Token']),False)

        concur = ConcurClient()

        reports = concur.validate_response(concur.api('v3.0/expense/reports',
                                                params={'access_token': token}))
        for (k, report_arr) in reports[1]['Reports']['Items'].iteritems():
            # print '%s: %s' % (k, v)
            for rep in report_arr:
                print 'ID: %s' % rep['ID']
                print 'Name: %s' % rep['Name']
                print 'HasException: %s' % rep['HasException']
                print 'ReceiptsReceived: %s' % rep['ReceiptsReceived']
                print 'Total: %s' % rep['Total']
                print '===================='
                # for (k1, v1) in rep.iteritems():
                #    print '%s: %s' % (k1, v1)

            #sorted_x = sorted(report_arr[0].iteritems(), key=operator.itemgetter(1))

            list_headers = ["ID","Name","HasException","ReceiptsReceived","Total"]
            y = PrettyTable(list_headers)
            #get the first x for details:
            for rep in report_arr:
                list_row = [ rep['ID'],rep['Name'],rep['HasException'],rep['ReceiptsReceived'],rep['Total']]
                y.add_row(list_row)

            y.sortby = "ID"
            y.sort_key = operator.itemgetter(1)
            #print y

            y_html_str = y.get_html_string(attributes = {"style":"border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;"}, border=True, header=True, padding_width=2).encode("utf8")
            y_html_str = y_html_str.replace('<th>','<th style="border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;">')
            y_html_str = y_html_str.replace('<td>','<td style="border-width: 1px;padding: 3px;border-style: solid;border-color: black;">')

            #adding date in the beggining
            #y_html_str = '<h2 align="left"><b>From  %s  to  %s</b></h2></br>' % (periodFrom,periodTo) + y_html_str

            #br in the end
            y_html_str = y_html_str + '</br></br>'

            #y.format = True
            print y_html_str

        resp = concur.validate_response(concur.api('user/v1.0/user',
                                                   params={'access_token': token, 'loginID': loginID}))

        dict_userProfile = resp[1]
        prefix = 'ns0:'
        isExpenseApprover = (True if dict_userProfile[prefix
                                                      + 'UserProfile'][prefix + 'ExpenseApprover'
                                                                       ] == 'Y' else False)
        isInvoiceApprover = (True if dict_userProfile[prefix
                                                      + 'UserProfile'][prefix + 'InvoiceApprover'
                                                                       ] == 'Y' else False)
        print isExpenseApprover
        print isInvoiceApprover


if __name__ == '__main__':
    test()
