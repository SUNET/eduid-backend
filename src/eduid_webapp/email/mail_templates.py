# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#


verification_email_en_text = '''
Thank you for registering with {site_name}.

To confirm that you own this email address, simply click on the following link:

{verification_link}

If clicking on the link above does not work, go to your profile and emails section. Click on the
verification icon and enter the following code:

{code}
'''

verification_email_en_html = '''
<html>
<head>
</head>
<body>
<p>Thank you for registering with <a href="{site_url}">{site_name}</a>.</p>

<p>To confirm that you own this email address, simply click on the following link:

<a href="{verification_link}">{verification_link}</a></p>

<p>If clicking on the link above does not work, go to your profile and emails section. Click on the
confirmation icon and enter the following code:</p>

<p><strong>{code}</strong></p>

</body>
</html>
'''

verification_email_sv_text = '''
Tack för din registrering med {site_name}.

För att bekräfta att du äger denna e-postadress klicka på länken nedan:

{verification_link}

Om länken ovan inte fungerar, gå till din profilsida och välj e-post.
Klicka på bekräftelsekoden och ange följande bekräftelsekod:

{code}
'''

verification_email_sv_html = '''
<html>
<head>
</head>
<body>
<p>Tack för din registrering med <a href="{site_url}">{site_name}</a>.</p>

<p>För att bekräfta att du äger denna e-postadress klicka på länken nedan:</p>

<p><a href="{verification_link}">{verification_link}</a></p>

<p>Om länken ovan inte fungerar, gå till din profilsida och välj e-post.
Klicka på bekräftelsekoden och ange följande bekräftelsekod:</p>

<p><strong>{code}</strong></p>
</body>
</html>
'''

verification_email =  {
    'en': {
        'text' : verification_email_en_text,
        'html' : verification_email_en_html
    },
    'sv': {
        'text' : verification_email_sv_text,
        'html' : verification_email_sv_html
    }
}
