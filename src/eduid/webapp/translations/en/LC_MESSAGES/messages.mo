??    l      |              ?    ?  ?   ?  Y  ?  ?   ?
    ?  P   ?  ?   ?  ?   ?  ?   ?  ?   ?  ?   ?  ?    :  ?    ?  ?   ?  ?   ?  %  ?  ?  ?  ?  ?  &  H  f  o  4  ?  f   !  "   r!     ?!  ?   ?!  ?   G"  x   ?"  1   b#  ?   ?#      C$  7   d$     ?$     ?$     ?$  7   ?$  (    %  Z   )%  L   ?%     ?%     ?%     ?%     &  7   &  #   M&     q&     w&     ?&     ?&     ?&     ?&     ?&     ?&     '     '  	    '     *'  	   3'     ='     V'     j'     ?'  ,   ?'     ?'     ?'  ?   ?'     ;(     K(     j(     y(     ?(  $   ?(  :   ?(     )     $)     -)     >)     Q)     ^)     f)  (   n)     ?)     ?)     ?)     ?)     ?)     ?)  $   ?)  #   *  %   =*     c*  	   u*     *     ?*     ?*     ?*  	   ?*     ?*     +     +     )+     9+     E+     e+  3   h+     ?+  1   ?+  ?  ?+    z-  ?   ?.  Y  8/  ?   ?1    '2  P   F3  ?   ?3  ?   &4  ?   ?4  ?   x5  ?   &6  ?  ?6  :  U8    ?9  ?   ?:  ?   ?;  %  f<  ?  ?@  ?  DB  &  ?C  f  E  4  sF  f   ?G  "   H     2H  ?   @H  ?   ?H  x   ?I  1   ?I  ?   1J      ?J  7   K     9K     GK     YK  7   eK  (   ?K  Z   ?K  L   !L     nL     ?L     ?L     ?L  7   ?L  #   ?L     M     M     #M     'M     =M     NM     mM     ?M     ?M     ?M  	   ?M     ?M  	   ?M     ?M     ?M     N     N  ,   :N     gN     yN  ?   ?N     ?N     ?N     O     O     -O  $   MO  :   rO     ?O     ?O     ?O     ?O     ?O     ?O     P  (   P     4P     IP     OP     WP     cP     P  $   ?P  #   ?P  %   ?P      Q  	   Q     Q     9Q     IQ     hQ  	   |Q     ?Q     ?Q     ?Q     ?Q     ?Q     ?Q     R  3   R     9R  1   SR   

<h2>Welcome to %(site_name)s,</h2>

<p>You recently signed up for <a href="%(site_url)s">%(site_name)s</a>.</p>

<p>Please confirm the e-mail address and get your password by clicking on this link:</p>

<a href="%(verification_link)s">%(verification_link)s</a>

 

Welcome to %(site_name)s,

You recently signed up for %(site_name)s.

Please confirm the e-mail address and get your password by clicking on this link:

  %(verification_link)s

 
                            <p><strong>Choose a strong password</strong></p>
                            <p>Some tips:</p>
                            <ul>
                                <li>Use upper- and lowercase characters (preferably not in the beginning or end)</li>
                                <li>Add digits somewhere else than at the end of the password</li>
                                <li>Add special characters, such as &#64; &#36; &#92; &#43; &#95; &#37;</li>
                                <li>Spaces are ignored</li>
                            </ul>
                         
                <p>Password has been updated successfully.</p>
                <p><a href="%(login_url)s">Return to login page</a></p>
             
            Please choose a new password for your eduID account. A strong password has been generated for you.
            You can accept the generated password by clicking "Change password" or you can opt to choose your
            own password by clicking "Custom Password".
         
          <p>Access cannot be granted at this time. Please try again later.</p> 
          <p>Access to the requested service could not be granted.
              The service might have requested a 'confirmed' identity.</p> 
          <p>Access to the requested service could not be granted.
              The service provider requires use of a 'confirmed' Security Key (SWAMID MFA/MFA HI).
          </p> 
          <p>Access to the requested service could not be granted.
              The service provider requires use of a Security Key (MFA).
          </p> 
          <p>The password has expired, because it had not been used in 18 months.</p>
	  <p>To regain access to the account, a reset of the credential is necessary.</p>
	   
          <p>This user account has been terminated.</p>
	  <p>To regain access to the account, a reset of the credential is necessary.</p>
	   
    <p>Hi,</p>
    <p>You are invited to join the group %(group_display_name)s with your <a href=%(site_url)s>%(site_name)s</a> account.</p>
    <p>To accept or decline the invitation go to <a href=%(group_invite_url)s>%(group_invite_url)s</a>.</p>
    <p>If you do not have an %(site_name)s account you can <a href="%(site_url)s">create one</a>.</p>
    <p>(This is an automated email. Please do not reply.)</p>
 
    <p>You have chosen to terminate your account at <a href="%(site_url)s">%(site_name)s</a>.</p>

    <p><strong>If you did not initiate this action please reset your password immediately.</strong></p>

    <p>Thank you for using %(site_name)s.</p>

    <p>(This is an automated email. Please do not reply.)</p>
 
    <p>You have tried to verify your account at <a href="%(site_url)s">%(site_name)s</a>.</p>
    <p>We encountered a problem and kindly ask you to verify you account again using a different verification method.</p>
    <p>We apologize for any inconvenience.</p>
 
    You have chosen to terminate your account at %(site_name)s.

    If you did not initiate this action please reset your password immediately.

    Thank you for using %(site_name)s.

    (This is an automated email. Please do not reply.)
 
    You have tried to verify your account at %(site_name)s

    We encountered a problem and kindly ask you to verify you account again using a different verification method.

    We apologize for any inconvenience.
 
<div id="text_frame" style="font-size: 12pt">
    <h4>Welcome to confirm your eduID account</h4>

    <div id="notice-frame">
        <div style="padding-top: 15px; margin-left: 15px;">
            Username: %(recipient_primary_mail_address)s<br/>
            Confirmation code: %(recipient_verification_code)s<br/>
            <strong>The code is valid until %(recipient_validity_period)s.</strong><br/>
        </div>
    </div>
    <div style="padding-top: 50px;">
        <strong>Instructions:</strong>
    </div>
    <ol>
        <li>Log in to https://dashboard.eduid.se with the username above and the
            password you used when you created your account.
        </li>
        <li>Open the tab "Identity".</li>
        <li>Click the card "BY POST" below "Verify your id number".</li>
        <li>Input the confirmation code in the window that opens.</li>
        <li>Click "OK".</li>
    </ol>
    <div style="padding-top: 50px;">
        If you did not request this letter from eduID then please report it to support@eduid.se.
    </div>
</div>
 
<p>Hi,</p>
<p>You recently asked to reset your password for your %(site_name)s account.</p>
<p>To change your password, click the link below:</p>
<p><a href="%(reset_password_link)s">%(reset_password_link)s</a></p>
<p>If clicking the link does not work you can copy and paste it into your browser.</p>
<p>The password reset link is valid for %(password_reset_timeout)s hours.</p>
<p>(This is an automated email. Please do not reply.)</p>
 
<p>Thank you for registering with <a href="%(site_url)s">%(site_name)s</a>.</p>

<p>To confirm that you own this email address, simply click on the following link:

<a href="%(verification_link)s">%(verification_link)s</a></p>

<p>If clicking on the link above does not work, go to your profile and emails section. Click on the
confirmation icon and enter the following code:</p>

<p><strong>%(code)s</strong></p>

 
Hi,

You are invited to join the group %(group_display_name)s with your %(site_name)s account.

To accept or decline the invitation go to %(group_invite_url)s.

If you do not have an %(site_name)s account you can create one at
%(site_url)s.

(This is an automated email. Please do not reply.)
 
Hi,

You recently asked to reset your password for your %(site_name)s account.

To change your password, click the link below:

%(reset_password_link)s

If clicking the link does not work you can copy and paste it into your browser.

The password reset link is valid for %(password_reset_timeout)s hours.

(This is an automated email. Please do not reply.)
 
Thank you for registering with %(site_name)s.

To confirm that you own this email address, simply click on the following link:

%(verification_link)s

If clicking on the link above does not work, go to your profile and emails section. Click on the
verification icon and enter the following code:

%(code)s

 
This is your one-time phone number verification code for %(site_name)s.

Code: %(verification_code)s
 %(site_name)s account verification 404 Not found <p>Please try again.</p>
          <p>There is a link (Forgot your password?) on the login page if you do not remember
              your username or password.</p> <p>Sorry, but the requested page is unavailable due to a server hiccup.</p>
          <p>Our engineers have been notified already, so please try again later.</p> <p>The login request could not be processed.</p>
          <p>Try emptying the browsers cache and re-initiate login.</p> <p>The requested resource could not be found.</p> <p>You are already logged in.</p>
          <p>If you got here by pressing 'back' in your browser,
              you can press 'forward' to return to where you came from.</p> A stronger password is required. Accept
                                        password Access denied Already logged in Bad Request Change
                                        password Choose an option to enhance the security Continue with no extra security. I understand that I will have to verify my account again. Copy and save the above password somewhere safe and click "Accept password". Credential expired Email address Email address not validated Email: Enter an email address registered to your account below Enter the code you received via SMS Error Extra security FAQ Forgot your password? Group invitation Incorrect username or password Invalid code. Please try again. Invalid email address Link expired New password Not Found Password Password: Passwords does not match Please enter a code Please enter a password Please repeat the password Please restart the password reset procedure. Please try again. Please use a stronger password Please use the password reset link that you have in your email. Repeat password Resend code or try another way Reset password Reset password - Email Reset password - Extra security Reset password - Verify phone number Reset password message sent. Check your email to continue. Reset your password SMS code SMS code expired Send SMS to number Server Error Sign in Sign up Something failed, or Javascript disabled Something went wrong Staff Student Technicians Temporary technical problem Terminate account The password reset link has expired. The phone verification has expired. The requested state can not be found. Too many requests Try again Type the same password again User terminated Username or password incorrect Verify phone number Visit the Your generated password is eduID Login eduID confirmation email eduID dashboard eduID login eduid-signup verification email en to confirm your Security Key (on the Security tab). to confirm your identity. to register a Security Key (on the Security tab). Project-Id-Version: eduid-webapp 0.2.27
Report-Msgid-Bugs-To: EMAIL@ADDRESS
POT-Creation-Date: 2021-02-18 10:23+0100
PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE
Last-Translator: FULL NAME <EMAIL@ADDRESS>
Language: en
Language-Team: en <LL@li.org>
Plural-Forms: nplurals=2; plural=(n != 1)
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit
Generated-By: Babel 2.9.0
 

<h2>Welcome to %(site_name)s,</h2>

<p>You recently signed up for <a href="%(site_url)s">%(site_name)s</a>.</p>

<p>Please confirm the e-mail address and get your password by clicking on this link:</p>

<a href="%(verification_link)s">%(verification_link)s</a>

 

Welcome to %(site_name)s,

You recently signed up for %(site_name)s.

Please confirm the e-mail address and get your password by clicking on this link:

  %(verification_link)s

 
                            <p><strong>Choose a strong password</strong></p>
                            <p>Some tips:</p>
                            <ul>
                                <li>Use upper- and lowercase characters (preferably not in the beginning or end)</li>
                                <li>Add digits somewhere else than at the end of the password</li>
                                <li>Add special characters, such as &#64; &#36; &#92; &#43; &#95; &#37;</li>
                                <li>Spaces are ignored</li>
                            </ul>
                         
                <p>Password has been updated successfully.</p>
                <p><a href="%(login_url)s">Return to login page</a></p>
             
            Please choose a new password for your eduID account. A strong password has been generated for you.
            You can accept the generated password by clicking "Change password" or you can opt to choose your
            own password by clicking "Custom Password".
         
          <p>Access cannot be granted at this time. Please try again later.</p> 
          <p>Access to the requested service could not be granted.
              The service might have requested a 'confirmed' identity.</p> 
          <p>Access to the requested service could not be granted.
              The service provider requires use of a 'confirmed' Security Key (SWAMID MFA/MFA HI).
          </p> 
          <p>Access to the requested service could not be granted.
              The service provider requires use of a Security Key (MFA).
          </p> 
          <p>The password has expired, because it had not been used in 18 months.</p>
	  <p>To regain access to the account, a reset of the credential is necessary.</p>
	   
          <p>This user account has been terminated.</p>
	  <p>To regain access to the account, a reset of the credential is necessary.</p>
	   
    <p>Hi,</p>
    <p>You are invited to join the group %(group_display_name)s with your <a href=%(site_url)s>%(site_name)s</a> account.</p>
    <p>To accept or decline the invitation go to <a href=%(group_invite_url)s>%(group_invite_url)s</a>.</p>
    <p>If you do not have an %(site_name)s account you can <a href="%(site_url)s">create one</a>.</p>
    <p>(This is an automated email. Please do not reply.)</p>
 
    <p>You have chosen to terminate your account at <a href="%(site_url)s">%(site_name)s</a>.</p>

    <p><strong>If you did not initiate this action please reset your password immediately.</strong></p>

    <p>Thank you for using %(site_name)s.</p>

    <p>(This is an automated email. Please do not reply.)</p>
 
    <p>You have tried to verify your account at <a href="%(site_url)s">%(site_name)s</a>.</p>
    <p>We encountered a problem and kindly ask you to verify you account again using a different verification method.</p>
    <p>We apologize for any inconvenience.</p>
 
    You have chosen to terminate your account at %(site_name)s.

    If you did not initiate this action please reset your password immediately.

    Thank you for using %(site_name)s.

    (This is an automated email. Please do not reply.)
 
    You have tried to verify your account at %(site_name)s

    We encountered a problem and kindly ask you to verify you account again using a different verification method.

    We apologize for any inconvenience.
 
<div id="text_frame" style="font-size: 12pt">
    <h4>Welcome to confirm your eduID account</h4>

    <div id="notice-frame">
        <div style="padding-top: 15px; margin-left: 15px;">
            Username: %(recipient_primary_mail_address)s<br/>
            Confirmation code: %(recipient_verification_code)s<br/>
            <strong>The code is valid until %(recipient_validity_period)s.</strong><br/>
        </div>
    </div>
    <div style="padding-top: 50px;">
        <strong>Instructions:</strong>
    </div>
    <ol>
        <li>Log in to https://dashboard.eduid.se with the username above and the
            password you used when you created your account.
        </li>
        <li>Open the tab "Identity".</li>
        <li>Click the card "BY POST" below "Verify your id number".</li>
        <li>Input the confirmation code in the window that opens.</li>
        <li>Click "OK".</li>
    </ol>
    <div style="padding-top: 50px;">
        If you did not request this letter from eduID then please report it to support@eduid.se.
    </div>
</div>
 
<p>Hi,</p>
<p>You recently asked to reset your password for your %(site_name)s account.</p>
<p>To change your password, click the link below:</p>
<p><a href="%(reset_password_link)s">%(reset_password_link)s</a></p>
<p>If clicking the link does not work you can copy and paste it into your browser.</p>
<p>The password reset link is valid for %(password_reset_timeout)s hours.</p>
<p>(This is an automated email. Please do not reply.)</p>
 
<p>Thank you for registering with <a href="%(site_url)s">%(site_name)s</a>.</p>

<p>To confirm that you own this email address, simply click on the following link:

<a href="%(verification_link)s">%(verification_link)s</a></p>

<p>If clicking on the link above does not work, go to your profile and emails section. Click on the
confirmation icon and enter the following code:</p>

<p><strong>%(code)s</strong></p>

 
Hi,

You are invited to join the group %(group_display_name)s with your %(site_name)s account.

To accept or decline the invitation go to %(group_invite_url)s.

If you do not have an %(site_name)s account you can create one at
%(site_url)s.

(This is an automated email. Please do not reply.)
 
Hi,

You recently asked to reset your password for your %(site_name)s account.

To change your password, click the link below:

%(reset_password_link)s

If clicking the link does not work you can copy and paste it into your browser.

The password reset link is valid for %(password_reset_timeout)s hours.

(This is an automated email. Please do not reply.)
 
Thank you for registering with %(site_name)s.

To confirm that you own this email address, simply click on the following link:

%(verification_link)s

If clicking on the link above does not work, go to your profile and emails section. Click on the
verification icon and enter the following code:

%(code)s

 
This is your one-time phone number verification code for %(site_name)s.

Code: %(verification_code)s
 %(site_name)s account verification 404 Not found <p>Please try again.</p>
          <p>There is a link (Forgot your password?) on the login page if you do not remember
              your username or password.</p> <p>Sorry, but the requested page is unavailable due to a server hiccup.</p>
          <p>Our engineers have been notified already, so please try again later.</p> <p>The login request could not be processed.</p>
          <p>Try emptying the browsers cache and re-initiate login.</p> <p>The requested resource could not be found.</p> <p>You are already logged in.</p>
          <p>If you got here by pressing 'back' in your browser,
              you can press 'forward' to return to where you came from.</p> A stronger password is required. Accept
                                        password Access denied Already logged in Bad Request Change
                                        password Choose an option to enhance the security Continue with no extra security. I understand that I will have to verify my account again. Copy and save the above password somewhere safe and click "Accept password". Credential expired Email address Email address not validated Email: Enter an email address registered to your account below Enter the code you received via SMS Error Extra security FAQ Forgot your password? Group invitation Incorrect username or password Invalid code. Please try again. Invalid email address Link expired New password Not Found Password Password: Passwords does not match Please enter a code Please enter a password Please repeat the password Please restart the password reset procedure. Please try again. Please use a stronger password Please use the password reset link that you have in your email. Repeat password Resend code or try another way Reset password Reset password - Email Reset password - Extra security Reset password - Verify phone number Reset password message sent. Check your email to continue. Reset your password SMS code SMS code expired Send SMS to number Server Error Sign in Sign up Something failed, or Javascript disabled Something went wrong Staff Student Technicians Temporary technical problem Terminate account The password reset link has expired. The phone verification has expired. The requested state can not be found. Too many requests Try again Type the same password again User terminated Username or password incorrect Verify phone number Visit the Your generated password is eduID Login eduID confirmation email eduID dashboard eduID login eduid-signup verification email en to confirm your Security Key (on the Security tab). to confirm your identity. to register a Security Key (on the Security tab). 