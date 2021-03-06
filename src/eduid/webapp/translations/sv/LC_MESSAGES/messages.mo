??    l      |              ?    ?  ?   ?  Y  ?  ?   ?
    ?  P   ?  ?   ?  ?   ?  ?   ?  ?   ?  ?   ?  ?    :  ?    ?  ?   ?  ?   ?  %  ?  ?  ?  ?  ?  &  H  f  o  4  ?  f   !  "   r!     ?!  ?   ?!  ?   G"  x   ?"  1   b#  ?   ?#      C$  7   d$     ?$     ?$     ?$  7   ?$  (    %  Z   )%  L   ?%     ?%     ?%     ?%     &  7   &  #   M&     q&     w&     ?&     ?&     ?&     ?&     ?&     ?&     '     '  	    '     *'  	   3'     ='     V'     j'     ?'  ,   ?'     ?'     ?'  ?   ?'     ;(     K(     j(     y(     ?(  $   ?(  :   ?(     )     $)     -)     >)     Q)     ^)     f)  (   n)     ?)     ?)     ?)     ?)     ?)     ?)  $   ?)  #   *  %   =*     c*  	   u*     *     ?*     ?*     ?*  	   ?*     ?*     +     +     )+     9+     E+     e+  3   h+     ?+  1   ?+  ?  ?+     ?-  ?   ?.  o  ?/  ?   1  ?   ?1  T   ?2  ?   ?2  ?   z3  ?   24  ?   ?4  ?   ?5  ?  6  M  ?7  ?    9    ?9  ?   ?:  I  ?;  ?  @  ?  ?A  8  ?C  ?  ?D  9  gF  s   ?G     H     4H  ?   FH  ?   ?H  ?   }I     J  ?   $J     ?J     K     (K     7K     FK     [K  (   lK  g   ?K  d   ?K  ,   bL     ?L  #   ?L     ?L  7   ?L  /    M     0M     4M     DM     TM     kM  '   yM  2   ?M     ?M     ?M     ?M     N  	   N  
   )N     4N     JN     VN     iN  6   ~N     ?N  )   ?N  T   ?N     MO  *   `O     ?O     ?O  '   ?O  /   ?O  _   P     xP     ?P     ?P     ?P  	   ?P     ?P     ?P  2   ?P     'Q  
   7Q     BQ     JQ     SQ     kQ  4   yQ  "   ?Q     ?Q     ?Q     R     R     6R  +   GR     sR     ?R     ?R     ?R     ?R     ?R     ?R     ?R     S  B   S  !   SS  B   uS   

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
PO-Revision-Date: 2018-03-27 09:25+0000
Last-Translator: Johan Lundberg <lundberg@sunet.se>, 2021
Language: sv
Language-Team: Swedish (https://www.transifex.com/sunet/teams/84844/sv/)
Plural-Forms: nplurals=2; plural=(n != 1)
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit
Generated-By: Babel 2.9.0
 

<h2>Välkommen till %(site_name)s,</h2>

<p>Du anmälde dig nyligen till <a href="%(site_url)s">%(site_name)s</a>.</p>

<p>Var vänlig bekräfta e-postadressen och få ditt lösenord genom att klicka på den här länken:</p>

<a href="%(verification_link)s">%(verification_link)s</a>

 

Välkommen till %(site_name)s,

Du anmälde dig nyligen till %(site_name)s.

Var vänlig bekräfta e-postadressen och få ditt lösenord genom att klicka på den här länken:

%(verification_link)s

 
<p><strong>Välj ett säkert lösenord.</strong></p>
<p>Några tips:</p>
<ul>
<li>Använd stora och små bokstäver (inte bara första bokstaven)</li>
<li>Lägg till en eller flera siffror någonstans i mitten av lösenordet</li>
<li>Använd specialtecken som &#64; &#36; &#92; &#43; &#95; &#37;</li>
<li>Blanksteg (mellanslag) ignoreras</li>
</ul>
                  
                <p>Lösenordet har ändrats.</p>
                <p><a href="%(login_url)s">Tillbaka till inloggningssidan</a></p>
             
Ändra lösenord för ditt eduID-konto. Ett säkert lösenord
har genererats åt dig.
Du kan acceptera det med knappen "Acceptera lösenord" eller så kan du välja att använda ett eget lösenord om du klickar på fliken "Eget lösenord". 
            <p>Åtkomst kan inte ges för tillfället. Var god försök senare.</p> 
            <p>Tillgång till den önskade tjänsten kunde inte ges.
                Tjänsten begärde förmodligen en verifierad identitet.</p> 
           <p>Tillgång till den önskade tjänsten kunde inte ges.
               Tjänsten kräver att en verifierad Säkerhetsnyckel (SWAMID MFA/MFA HI) används.
            </p> 
           <p>Tillgång till den önskade tjänsten kunde inte ges.
               Tjänsten kräver att Säkerhetsnyckel (MFA) används.
            </p> 
          <p>Giltighetstiden på lösenordet har gått ut eftersom det inte har använts på 18 månader.</p>
	  <p>För att kunna logga in igen så måste lösenordet återställas.</p>
	 
            <p>Det här kontot har tagits bort.</p>
	  <p>För att få tillgång till kontot igen så måste lösenordet återställas.</p>
	 
<p>Hej,</p>
<p>Du är inbjuden att gå med i gruppen %(group_display_name)smed ditt <a href=%(site_url)s>%(site_name)s-konto</a>.
<p>För att acceptera inbjudan gå till <a href=%(group_invite_url)s>%(group_invite_url)s</a>.</p>
<p>Om du inte redan har ett %(site_name)s-konto så kan du <a href="%(site_url)s">skapa ett</a>.</p>
<p>(Detta är ett automatiserat meddelande och går ej att svara på.)</p>
 
    <p>Du har valt att ta bort ditt <a href="%(site_url)s">%(site_name)s</a>-konto.</p>

    <p><strong>Om det inte var du som tog bort kontot så återställ ditt lösenord omedelbart.</strong></p>

    <p>Tack för att du använde %(site_name)s.</p>

    <p>(Detta är ett automatiserat meddelande och går ej att svara på.)</p>
 
<p>Du har försökt bekräfta ditt konto hos<a href="%(site_url)s">%(site_name)s</a>.</p>
<p>Tyvärr uppstod ett problem så vi måste be dig att bekräfta ditt konto igen med något av de andra sätten att verifiera din identitet.</p>
 
    Du har valt att ta bort ditt %(site_name)s-konto.

    Om det inte var du som tog bort kontot så återställ ditt lösenord omedelbart.

    Tack för att du använde %(site_name)s.

    (Detta är ett automatiserat meddelande och går ej att svara på.)
 
Du har försökt bekräfta ditt konto hos%(site_name)s.

Tyvärr uppstod ett problem så vi måste be dig att bekräfta ditt konto igen med något av de andra sätten att verifiera din identitet.
 
<div id="text_frame" style="font-size: 12pt">
    <h4>Välkommen att bekräfta ditt eduID-konto</h4>

    <div id="notice-frame">
        <div style="padding-top: 15px; margin-left: 15px;">
            Användarnamn: %(recipient_primary_mail_address)s<br/>
            Bekräftelsekod: %(recipient_verification_code)s<br/>
            <strong>Koden är giltig till och med: %(recipient_validity_period)s</strong><br/>
        </div>
    </div>
    <div style="padding-top: 50px;">
        <strong>Instruktioner:</strong>
    </div>
    <ol>
        <li>Logga in på https://dashboard.eduid.se med användarnamnet ovan och det
            lösenord som du använde när du skapade ditt konto.
        </li>
        <li>Öppna fliken "Identitet".</li>
        <li>Klicka på rutan "VIA POST" under "Bekräfta ditt personnummer".</li>
        <li>Skriv in bekräftelsekoden i rutan som öppnas.</li>
        <li>Klicka på "OK".</li>
    </ol>
    <div style="padding-top: 50px;">
        Om du inte har begärt en kod från eduID vänligen rapportera detta till support@eduid.se.
    </div>
</div>
 
<p>Hej,</p>
<p>Du har bett om att byta lösenord för ditt %(site_name)s-konto.</p>
<p>För att byta lösenord, klicka på länken nedan:</p>
<p><a href="%(reset_password_link)s">%(reset_password_link)s</a></p>
<p>Om det inte går att klicka på länken kan du kopiera och klistra in den i din webbläsare.</p>
<p>Länken för återställning av ditt lösenord är giltig i %(password_reset_timeout)s timmar.</p>
<p>(Detta är ett automatiserat meddelande och går ej att svara på.)</p>
 
<p>Tack för att du registrerade dig hos <a href="%(site_url)s">%(site_name)s</a>.</p>

<p>Lättaste sättet att bekräfta din mejladress är att klicka på länken nedan:

<a href="%(verification_link)s">%(verification_link)s</a></p>

<p>Fungerar inte länken så kan du logga in på din profil, gå till e-post-fliken och klicka på bekräfta. Klistra sedan in nedanstående kod:</p>

<p><strong>%(code)s</strong></p>

 
Hej,

Du är inbjuden att gå med i gruppen %(group_display_name)s med ditt %(site_name)s-konto.

För att acceptera inbjudan gå till %(group_invite_url)s.

Om du inte redan har ett %(site_name)s-konto så kan du skapa ett på %(site_url)s.

(Detta är ett automatiserat meddelande och går ej att svara på.)
 
Hej,

Du har bett om att byta lösenord för ditt %(site_name)s-konto.

För att byta lösenord, klicka på länken nedan:

%(reset_password_link)s

Om det inte går att klicka på länken kan du kopiera och klistra in den i din webbläsare.

Länken för återställning av ditt lösenord är giltig i %(password_reset_timeout)s timmar.

(Detta är ett automatiserat meddelande och går ej att svara på.)
 
Tack för att du registrerade dig hos%(site_name)s.

Lättaste sättet att bekräfta din mejladress är att klicka på länken nedan:

%(verification_link)s

Fungerar inte länken så kan du logga in på din profil, gå till e-post-fliken och klicka på bekräfta. Klistra sedan in nedanstående kod:

%(code)s

 
Det här är din engångskod för att verifiera ditt telefonnummer hos %(site_name)s.

Kod: %(verification_code)s
 %(site_name)skontobekräftning 404 Hittades inte <p>Var god försök igen.</p>
          <p>Det finns en länk (Glömt ditt lösenord?) på inloggningssidan om du inte kommer ihåg
 ditt användarnamn eller lösenord.</p> <p>Hoppsan, sidan kan inte visas på grund av ett serverfel.</p>
          <p>Våra tekniker har meddelats, så försök igen senare.</p> <p>Inloggningsförsöket misslyckades.</p>
          <p>Börja med att tömma webbläsarens cache och försök sedan logga in igen.</p> <p>Sidan kunde inte hittas</p> <p>Du är redan inloggad.</p>
           <p>Om du kom hit genom att använda 'Tillbaka'-knappen i din webbläsare
               så kan du klicka på 'Framåt'-knappen för att komma tillbaka dit du var.</p> Ett starkare lösenord krävs. Acceptera lösenord Åtkomst nekad Redan inloggad Felaktig förfrågan Ändra lösenord Välj en metod för att öka säkerheten Fortsätt utan extra säkerhet. Jag förstår att det betyder att jag måste bekräfta mitt konto igen. Kopiera och spara det ovanstående lösenordet på en säker plats och klicka "Acceptera lösenord". Giltighetstiden på lösenordet har gått ut E-postadress E-postadressen kunde inte valideras E-post: Ange en e-postadress som är registrerad på ditt konto Ange bekräftelsekoden som har skickats med SMS Fel Extra säkerhet Vanliga frågor Glömt ditt lösenord? Gruppinbjudan Felaktigt användarnamn eller lösenord Felaktig bekräftelsekod. Vänligen försök igen. Ogiltig e-postadress Länken har gått ut Nytt lösenord Kunde inte hittas Lösenord Lösenord: Lösenorden är olika Ange en kod Ange ett lösenord Repetera lösenordet Var vänlig och börja om lösenordsåterställningen. Vänligen försök igen. Lösenordet är inte tillräckligt starkt Var vänlig och använd återställningslänken som skickats till din e-postsadress. Repetera lösenord Skicka en ny kod eller byt säkerhetsmetod Återställ lösenord Återställ lösenord - E-post Återställ lösenord - Extra säkerhet Återställ lösenord - Bekräfta telefonnummer Ett meddelande om lösenordsåterställning har skickats. Kolla din e-post för att fortsätta. Återställ ditt lösenord SMS-bekräftelsekod SMS-koden har gått ut Skicka SMS till nummer Serverfel Logga in Skapa konto Något gick fel eller så är Javascript avstängt Något gick fel Anställda Student Tekniker Temporärt tekniskt fel Avsluta konto Länken för lösenordsåterställning har gått ut. Telefonbekräftelsen har gått ut. Kunde inte ladda sparad status För många förfrågningar Försök igen Skriv samma lösenord igen. Kontot borttaget Användarnamn eller lösenord är felaktigt Bekräfta telefonnummer Besök Ditt genererade lösenord är eduID-inloggning eduID bekräftelsemejl eduID dashboard eduID-inloggning eduID registrering one för att verifiera din Säkerhetsnyckel (under Säkerhets-tabben). för att verifiera din identitet. för att registrera en Säkerhetsnyckel (under Säkerhets-tabben). 