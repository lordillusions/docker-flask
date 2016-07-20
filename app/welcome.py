# -*- coding: utf-8 -*-
# Copyright 2015 IBM Corp. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import datetime
import urllib
from PIL import ImageFont,Image,ImageDraw
import xmltodict as xmltodict
import ConcurOAuthPython
from flask import Flask, jsonify, request, render_template, redirect, url_for, session, make_response
from concur import ConcurClient
import cStringIO
from prettytable import PrettyTable
import operator

from urlparse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

app = Flask(__name__)

UPLOAD_FOLDER = '/Users/wchaves/Pictures/'
ALLOWED_EXTENSIONS = set(['pdf', 'png', 'jpg', 'jpeg'])
BOX_NUMBER_FIELD = 'Custom8'

app.config.update(
    DEBUG=True,
)
app.secret_key = 'concur_prototype'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'concursecretmasterkey'
#app.config['SAML_PATH'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'saml')

APP_ROOT = os.path.dirname(os.path.abspath(__file__))   # refers to application_top
app.config['SAML_PATH'] = os.path.join(APP_ROOT, 'saml')




def text2png(text, color="#000", bgcolor="#FFF", fontfullpath=None, fontsize=13, leftpadding=3,
             rightpadding=3, width=200):
    REPLACEMENT_CHARACTER = '\u0a0a'
    NEWLINE_REPLACEMENT_STRING = ' ' + REPLACEMENT_CHARACTER + ' '

    font = ImageFont.load_default() if fontfullpath == None else ImageFont.truetype(fontfullpath, fontsize)
    text = text.replace('\n', NEWLINE_REPLACEMENT_STRING)

    lines = []
    line = u""

    for word in text.split():
        print word
        if word == REPLACEMENT_CHARACTER:  # give a blank line
            lines.append(line[1:])  # slice the white space in the begining of the line
            line = u""
            lines.append(u"")  # the blank line
        elif font.getsize(line + ' ' + word)[0] <= (width - rightpadding - leftpadding):
            line += ' ' + word
        else:  # start a new line
            lines.append(line[1:])  # slice the white space in the begining of the line
            line = u""

            # TODO: handle too long words at this point
            line += ' ' + word  # for now, assume no word alone can exceed the line width

    if len(line) != 0:
        lines.append(line[1:])  # add the last line

    line_height = font.getsize(text)[1]
    img_height = line_height * (len(lines) + 1)

    img = Image.new("RGBA", (width, img_height), bgcolor)
    #img = Image.new("RGB", (width, img_height), bgcolor)
    draw = ImageDraw.Draw(img)

    y = 0
    for line in lines:
        draw.text((leftpadding, y), line, color, font=font)
        y += line_height

    s = cStringIO.StringIO()
    img.save(s, 'PNG')
    in_memory_file = s.getvalue()
    return in_memory_file

def TextToImage(str_text,fontsize): #return image file PNG
    image = Image.new("RGBA", (600,150), (255,255,255))
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.truetype("Arial.ttf", fontsize)
    except:
        font = ImageFont.load_default()

    draw.text((10, 0), str_text, (0,0,0), font=font)
    img_resized = image.resize((450,150), Image.ANTIALIAS)

    s = cStringIO.StringIO()
    img_resized.save(s, 'PNG')
    in_memory_file = s.getvalue()
    #raw_img_data = img.tostring()

    return in_memory_file


def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    return auth


def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'query_string': request.query_string
    }


@app.route('/', methods=['GET', 'POST'])
def index():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    errors = []
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    if 'sso' in request.args:
        return redirect(auth.login())
    elif 'sso2' in request.args:
        return_to = '%sattrs/' % request.host_url
        return redirect(auth.login(return_to))
    elif 'slo' in request.args:
        name_id = None
        session_index = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']

        return redirect(auth.logout(name_id=name_id, session_index=session_index))
    elif 'acs' in request.args:
        auth.process_response()
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()
        if len(errors) == 0:
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            #print urllib.unquote(request.form['RelayState']).decode('utf8')
            if 'RelayState' in request.form and self_url != request.form['RelayState']:
                return redirect(auth.redirect_to(urllib.unquote(request.form['RelayState']).decode('utf8')))
    elif 'sls' in request.args:
        dscb = lambda: session.clear()
        url = auth.process_slo(delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return redirect(url)
            else:
                success_slo = True

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return render_template(
        'loginSSO.html',
        errors=errors,
        not_auth_warn=not_auth_warn,
        success_slo=success_slo,
        attributes=attributes,
        paint_logout=paint_logout
    )


@app.route('/attrs/')
def attrs():
    paint_logout = False
    attributes = False

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return render_template('attrs.html', paint_logout=paint_logout,
                           attributes=attributes)


@app.route('/metadata/')
def metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    return resp


# route for handling the login page logic
@app.route('/reportCreation', methods=['GET', 'POST'])
def reportCreation():
    error = None
    if 'token' in session:
        concur = ConcurClient()
        token = session['token']
        username = session['username']
        if request.method == 'POST':
            today = datetime.date.today()
            new_xml_update = {}
            new_xml_update['Report'] = {}
            #new_xml_update['Report']['ID'] = dict_resp_report['Report']['ID']
            new_xml_update['Report']['Name'] = request.form['Name']
            new_xml_update['Report']['Comment'] = request.form['Comment']

            xml_post = xmltodict.unparse(new_xml_update)

            content_type, resp_post = concur.validate_response(concur.api('v3.0/expense/reports', method='POST', params={'access_token': token},
                                                                            headers={'content-type': 'application/xml', 'accept':'*'}, data=xml_post))


            #print resp_post['Response']['ID']
            #print resp_post['Response']['URI']
            return render_template('reportCreationSuccess.html', username=username, reportURL=resp_post['Response']['URI'], reportID=resp_post['Response']['ID'], error=error)


        return render_template('reportCreation.html', username=username, error=error)
    else:
        return 'Invalid Token - Please Login /login'

# route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        access_token_full = ConcurOAuthPython.getTokenGivenUsernamePasswordAndConsumerKey(username, request.form['password'], 'FYB8YBa5ggY9HBEETbraKk')

        if access_token_full.has_key('Error'):
            error = 'Invalid Credentials. Please try again.'
        else:
            token = access_token_full['Access_Token']['Token']
            session['token'] = token
            session['username'] = username
            return redirect(url_for('receiptsInput'))

    return render_template('login.html', error=error)


@app.route('/reportsList', methods=['GET', 'POST'])
def reportsList():
    error = None
    if 'token' in session:
        concur = ConcurClient()
        token = session['token']
        username = session['username']

        content_type, reports = concur.validate_response(concur.api('v3.0/expense/reports',
                                                params={'access_token': token}))


        print token

        for (k, report_arr) in reports['Reports']['Items'].iteritems():
            # print '%s: %s' % (k, v)

            '''
            for rep in report_arr:
                print 'ID: %s' % rep['ID']
                print 'Name: %s' % rep['Name']
                print 'HasException: %s' % rep['HasException']
                print 'ReceiptsReceived: %s' % rep['ReceiptsReceived']
                print 'Total: %s' % rep['Total']
                print '===================='
                # for (k1, v1) in rep.iteritems():
                #    print '%s: %s' % (k1, v1)
            '''

            #sorted_x = sorted(report_arr[0].iteritems(), key=operator.itemgetter(1))

            list_headers = ["ID","Name","HasException","ReceiptsReceived","LastComment","Box Number","Total"]
            y = PrettyTable(list_headers)
            #get the first x for details:
            for rep in report_arr:
                for k1,v1 in rep.iteritems():
                    if str(k1).startswith('Custom'):
                        print k1,v1

                list_row = [ rep['ID'],
                             rep['Name'],
                             rep['HasException'],
                             rep['ReceiptsReceived'],
                             rep['LastComment'],
                             '' if not rep[BOX_NUMBER_FIELD].has_key('ListItemID') else rep[BOX_NUMBER_FIELD]['Value'],
                             rep['Total']]

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
            return render_template('reportsList.html', reportsList=y_html_str, username=username, error=error)




        return render_template('receiptsInput.html', username=username, isExpenseApprover=isExpenseApprover, isInvoiceApprover=isInvoiceApprover, error=error)
    else:
        return 'Invalid Token - Please Login /login'


@app.route('/receiptsInput', methods=['GET', 'POST'])
def receiptsInput():
    error = None
    if 'token' in session:
        concur = ConcurClient()
        token = session['token']
        username = session['username']
        #resp = concur.validate_response(concur.api('v3.0/expense/reports', params={'access_token': token}))
        content_type, userProfile = concur.validate_response(concur.api('user/v1.0/user', method='GET', params={'access_token': token, 'loginID': username}))
        prefix = 'ns0:'
        isExpenseApprover = True if userProfile[prefix + 'UserProfile'][prefix + 'ExpenseApprover'] == 'Y' else False
        isInvoiceApprover = True if userProfile[prefix + 'UserProfile'][prefix + 'InvoiceApprover'] == 'Y' else False

        if request.method == 'POST':
            receiptsNumbers = request.form['receiptsNumbers'].split('\n')

            counter = 1

            list_headers = ["Report ID","Status"]
            y = PrettyTable(list_headers)

            for rn in receiptsNumbers:
                if len(rn)>0:
                    #Retrieve The whole Report
                    response = concur.api('v3.0/expense/reports', method='GET', params={'access_token': token, 'id': rn.strip()})
                    resp_report = response.content
                    dict_resp_report = xmltodict.parse(resp_report)

                    #print dict_resp_report['Report']['Name']
                    #for k,v in dict_resp_report['Report'].iteritems():
                    #    print "%s:%s" % (k,v)

                    #if dict_resp_report['Report']['Custom15']['Type']=='List':
                    #    dict_resp_report['Report']['Custom15'] = dict_resp_report['Report']['Custom15']['ListItemID']


                    now = datetime.datetime.now()
                    new_xml_update = {}
                    new_xml_update['Report'] = {}
                    #new_xml_update['Report']['ID'] = dict_resp_report['Report']['ID']
                    new_xml_update['Report'][BOX_NUMBER_FIELD] = {}
                    new_xml_update['Report'][BOX_NUMBER_FIELD]['Value'] = 'Box Number:' + request.form['BoxNumber']
                    new_xml_update['Report']['Comment'] = now.strftime('Receipts Received at %m/%d/%Y %H:%M')
                    #new_xml_update['Report']['ReceiptsReceived'] = "Y"
                    #new_xml_update['Report']['Custom16'] = {}
                    #new_xml_update['Report']['Custom16']['Value'] = "true"
                    counter = counter + 1


                    b = bytearray(TextToImage(u'Country Code: ' + dict_resp_report['Report']['Country'] +
                            u'\nBox Number: ' + request.form['BoxNumber'] +
                            u'\nReport IDr: ' + dict_resp_report['Report']['ID'] +
                            u'\nYour Receipts Hardcopies have been Processed. ' +
                            u'\nAny Question Please Call: (555)555-5555',
                            16,
                            ))
                    '''
                    # Send dummy file
                    with open(UPLOAD_FOLDER + 'dummy_pic.png') as image_file:
                        f = image_file.read()

                        b = bytearray(text2png(u'Country Code: ' + dict_resp_report['Report']['Country'] +
                                u'\nBox Number: ' + request.form['BoxNumber'] +
                                u'\nReport IDr: ' + dict_resp_report['Report']['ID'] +
                                u'\nYour Receipts Hardcopies have been Processed. Any Question Please Call: (555)555-5555',
                                color = "#000",
                                bgcolor = "#FFF",
                                fontfullpath = None,
                                fontsize = 16,
                                leftpadding = 1,
                                rightpadding = 1,
                                width = 450,
                                ))
                    '''

                    #content_type, resp_file_post = concur.validate_response(concur.api('image/v1.0/report', method='POST', params={'access_token': token, 'id': rn.strip()},
                    content_type, resp_file_post = concur.validate_response(concur.api('image/v1.0/report/%s' % (rn.strip()), method='POST', params={'access_token': token},
                                                                                                    headers={'content-type': 'image/png', 'accept':'*'}, data=b))
                    print resp_file_post


                    #xml_update = xmltodict.unparse(dict_resp_report)
                    xml_update = xmltodict.unparse(new_xml_update)

                    print xml_update


                    #new report based on the last one
                    content_type, resp_update = concur.validate_response(concur.api('v3.0/expense/reports', method='PUT', params={'access_token': token, 'id': rn.strip()},
                                                                                    headers={'content-type': 'application/xml', 'accept':'*'}, data=xml_update))

                    #content_type, resp_update = concur.validate_response(concur.api('v3.0/expense/reports', method='POST', params={'access_token': token},
                    #                                                                headers={'content-type': 'application/xml', 'accept':'*'}, data=xml_post))

                    if resp_update['Response']=='no-content':
                        list_row = [ dict_resp_report['Report']['ID'],
                                     'Updated OK',
                                     ]
                    else:
                        list_row = [ dict_resp_report['Report']['ID'],
                                     'Updated FAIL',
                                     ]

                    y.add_row(list_row)


            y.sortby = "Report ID"
            y.sort_key = operator.itemgetter(1)
            #print y

            y_html_str = y.get_html_string(attributes = {"style":"border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;"}, border=True, header=True, padding_width=2).encode("utf8")
            y_html_str = y_html_str.replace('<th>','<th style="border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;">')
            y_html_str = y_html_str.replace('<td>','<td style="border-width: 1px;padding: 3px;border-style: solid;border-color: black;">')

            return render_template('receiptsInputResponse.html', reportsUpdatedList=y_html_str, username=username, error=error)

        return render_template('receiptsInput.html', username=username, isExpenseApprover=isExpenseApprover, isInvoiceApprover=isInvoiceApprover, error=error)
    else:
        return 'Invalid Token - Please Login /login'

port = os.getenv('PORT', '443')
if __name__ == "__main__":
    context = (os.path.join(APP_ROOT, 'saml/certs/sp.crt'), os.path.join(APP_ROOT, 'saml/certs/sp.key'))
    #app.run(host='0.0.0.0', port=int(port), debug=True) #no ssl
    app.run(host='0.0.0.0', port=int(port), ssl_context=context, threaded=True, debug=True)
    #app.run(host='0.0.0.0', ssl_context=context, threaded=True, debug=True)
