<?php

class HostingerApi
{
    protected $username = '';
    protected $password = '';
    protected $api_url = '';

    /**
     * $config['username'] string
     * $config['password'] string
     * $config['api_url']  string Must end with '/'
     *
     * @param array $config (See above)
     */
    public function __construct($config)
    {
        $this->username = $config['username'];
        $this->password = $config['password'];
        $this->api_url = $config['api_url'];
    }

    /**
     * @param string $name
     * @param string $email
     * @param string $subject
     * @param string $content
     * @return array
     * @throws HostingerApiException
     */
    public function publicTicketCreate($name, $email, $subject, $content){
        $params = array(
            'name' => $name,
            'email' => $email,
            'subject' => $subject,
            'content' => $content,
            'ip' => $this->getIp(),
        );
        return $this->make_call('v1/ticket/create_public', 'POST', $params);
    }

    /**
     * @param int $id
     * @return array
     * @throws HostingerApiException
     */
    public function clientGetById($id){
        return $this->make_call('v1/client/'.$id, 'GET', array());
    }

    /**
     * @param $hash
     * @return array
     * @throws HostingerApiException
     */
    public function clientGetByLoginHash($hash){
        return $this->make_call('v1/client/get-by-hash/'.$hash, 'GET', array());
    }

    /**
     * @param string $email
     * @return array
     * @throws HostingerApiException
     */
    public function clientGetByEmail($email){
        $params = array(
            'email' => $email
        );
        return $this->make_call('v1/client/get-by-email', 'GET', $params);
    }

    /**
     * @param string $email
     * @param string $password
     * @return array
     * @throws HostingerApiException
     */
    public function clientGetByEmailAndPassword($email, $password){
        $params = array(
            'email' => $email,
            'password' => $password,
        );
        return $this->make_call('v1/client/get-by-email-password', 'POST', $params);
    }

    /**
     * @param string $email
     * @return array
     * @throws HostingerApiException
     */
    public function clientPasswordRemind($email){
        $params = array(
            'email' => $email,
        );
        return $this->make_call('v1/client/password-remind', 'POST', $params);
    }

    /**
     * @param string $first_name
     * @param string $password
     * @param string $email
     * @param array $additionalParams
     * @return array
     * @throws HostingerApiException
     */
    public function clientCreate($first_name, $password, $email, $additionalParams = array())
    {
        $params = array(
            'email' => $email,
            'password' => $password,
            'first_name' => $first_name,
            'client_ip' => $this->getIp(),
        );

        $defaultAdditionalParams = array(
            'last_name' => '',
            'company' => '',
            'address_1' => '',
            'address_2' => '',
            'city' => '',
            'country' => '',
            'state' => '',
            'zip' => '',
            'phone' => '',
            'phone_cc' => '',
            'cpf' => '',
            'referral_id' => '',
            'reseller_client_campaign' => '',
            'reseller_client_campaign_source' => '',
            'r' => '',
        );

        $additionalParams = array_merge($defaultAdditionalParams, $additionalParams);
        $params = array_merge($additionalParams, $params);

        return $this->make_call('v1/client', 'POST', $params);
    }

    /**
     * @param $client_id
     * @param $title
     * @param array $ns_list = array(
            'ns1.custom.com',
            'ns2.custom.com',
            'ns3.custom.com',
            'ns4.custom.com',
     * ) or EMPTY ARRAY
     * @param array $contact['owner'] = array(
            'email'         => 'value', // REQUIRED
            'first_name'    => 'value', // REQUIRED
            'last_name'     => 'value', // REQUIRED
            'address_1'     => 'value', // REQUIRED
            'address_2'     => 'value',
            'company'       => 'value',
            'city'          => 'value', // REQUIRED
            'state'         => 'value', // REQUIRED
            'zip'           => 'value', // REQUIRED
            'country'       => 'value', // REQUIRED
            'phone'         => 'value', // REQUIRED
            'phone_cc'      => 'value', // REQUIRED
            'vat_code'      => 'value',
            'passport'      => 'value',
            'birth_date'    => 'value',
            'cpf'           => 'value',
     * )
     * @return array
     * @throws HostingerApiException
     */
    public function clientWhoisProfileCreate($client_id, $title, array $ns_list, array $contact) {
        if(!isset($contact['owner']) || empty($contact['owner'])) {
            throw new HostingerApiException('Owner contact is missing.');
        }

        $contact_types = array(
            'owner',
            'technical',
            'administrative',
            'billing',
        );

        $required_contact_fields = array(
            'email',
            'first_name',
            'last_name',
            'address_1',
            'city',
            'state',
            'zip',
            'country',
            'phone',
            'phone_cc',
        );

        foreach($contact_types as $contact_type) {
            if($contact_type != 'owner' && !isset($contact[$contact_type])) {
                $contact[$contact_type] = $contact['owner'];
            }
            foreach($required_contact_fields as $field) {
                if(!isset($contact[$contact_type][$field]) || empty($contact[$contact_type][$field])) {
                    throw new HostingerApiException($contact_type . ' field ' . $field . ' is missing or empty.');
                }
            }
        }

        $params = array(
            'client_id' => $client_id,
            'title' => $title,
            'ns_list' => $ns_list,
            'contact' => $contact,
        );
        return $this->make_call('v1/client/create-whois-profile', 'POST', $params);
    }

    /**
     * @param \Cart\Checkout $checkout
     * @param string $gatewayCode
     * @param string $campaign (utm_campaign)
     *
     * @return array
     * @throws HostingerApiException
     */
    public function cartOrderCreate($checkout, $gatewayCode, $campaign = '', $ip = '')
    {
        if (!$checkout instanceof \Cart\Checkout){
            throw new HostingerApiException('invalid checkout');
        }
        return $this->make_call('v1/cart', 'POST', array('checkout'=> $checkout->toArray(), 'gateway_code' => $gatewayCode, 'campaign' => $campaign, 'ip' => $ip));
    }

    /**
     * @param int $client_id
     * @return boolean
     * @throws HostingerApiException
     */
    public function cartAllowOrderFreeHosting($client_id)
    {
        if(empty($client_id)) {
            throw new HostingerApiException('Client Id is missing.');
        }
        return $this->make_call('v1/cart/allow-free-hosting/'.$client_id, 'GET', array());
    }

    /**
     * @param int $client_id
     * @param string $redirect
     * @return string Url to cpanel auto login
     * @throws HostingerApiException
     */
    public function clientGetAutoLoginUrl($client_id, $redirect = ''){
        $params = array(
            'r' => $redirect
        );
        return $this->make_call('v1/client/'.$client_id.'/login-url', 'GET', $params);
    }

    /**
     * @param string $from_email
     * @param string $from_name
     * @param string $to_email
     * @param string $to_name
     * @param string $subject
     * @param string $content_html
     * @param string $content_txt
     * @return array
     * @throws HostingerApiException
     */
    public function mailSend($from_email, $from_name, $to_email, $to_name, $subject, $content_html, $content_txt) {
        $params = array(
            'subject'       => $subject,
            'from_email'    => $from_email,
            'from_name'     => $from_name,
            'body_html'     => $content_html,
            'body_text'     => $content_txt,
            'to_email'      => $to_email,
            'to_name'       => $to_name,
        );
        return $this->make_call('v1/mail/send', 'POST', $params);
    }

    /**
     * @param $domain
     * @return bool
     * @throws HostingerApiException
     */
    public function domainIsAvailable($domain) {
        $result = $this->make_call('v1/domain/available?domain='.$domain, 'GET');
        return isset($result['available']) ? $result['available'] : false;
    }

    /**
     * @param $email
     * @param $domain
     * @return bool
     * @throws HostingerApiException
     */
    public function domainLotteryEntry($email, $domain) {
        $params = array(
            'email'       => $email,
            'domain'       => $domain,
        );
        return $this->make_call('v1/domain/lottery_entry', 'POST', $params);
    }

    /**
     * @param integer $client_id
     * @param float $amount
     * @return array
     * @throws HostingerApiException
     */
    public function paymentGatewayGetList($client_id = null, $amount = null) {
        $params = array();
        if(!empty($client_id)) {
            $params['client_id'] = $client_id;
        }
        if(!empty($amount)) {
            $params['amount'] = $amount;
        }
        return $this->make_call('v1/settings/payment-gateway-list', 'GET', $params);
    }

    /**
     * @param string $redirect_url
     * @danger ?hash={client.login.hash} will be added to $redirect_url after success social login
     * @info use clientGetByLoginHash() to get returned client from social login
     * @return array
     * @throws HostingerApiException
     */
    public function oauthProviderGetList($redirect_url, $is_cart = 0) {
        $params = array(
            'redirect' => $redirect_url,
            'is_cart' => $is_cart
        );
        return $this->make_call('v1/settings/oauth-list', 'POST', $params);
    }

    /**
     * @return array
     * @throws HostingerApiException
     */
    public function countryGetList() {
        return $this->make_call('v1/settings/country-list', 'GET', array());
    }

    /**
     * @return array
     * @throws HostingerApiException
     */
    public function countryPhoneCodeGetList() {
        return $this->make_call('v1/settings/phone-code-list', 'GET', array());
    }

    /**
     * @return array
     * @throws HostingerApiException
     */
    public function knowledgeBaseGetList() {
        return $this->make_call('v1/settings/knowledgebase', 'GET', array());
    }

    /**
     * Send transactional email for known client
     * @param string $event - event code name
     * @param int $client_id - client ID
     * @param array $params - params for the email template
     * @throws HostingerApiException
     * @return array
     */
    public function sendMailEventToClient($event, $client_id, $params = array()) {
        $params['client_id'] = $client_id;
        return $this->make_call('v1/mail/send/'.strtolower($event), 'POST', $params);
    }

    /**
     * Send transactional email when client id is not known, but email
     * @param string $event - event code name
     * @param string $email - valid email address
     * @param array $params - params for the email template
     * @throws HostingerApiException
     * @return array
     */
    public function sendMailEventToEmail($event, $email, $params = array()) {
        $params['email'] = strtolower($email);
        return $this->make_call('v1/mail/send/'.strtolower($event), 'POST', $params);
    }

    /**
     * @param $email - client email
     * @param $score - nps score 1 - 10
     * @return boolean
     * @throws HostingerApiException
     */
    public function reviewNetPromotionScoreCreate($email, $score, $comment = '', $account_type = '', $account_reason = '', $account_important = '', $account_not_important = '') {
        $params = array(
            'email' => $email,
            'recommend' => $score,
            'comment' => $comment,
            'account_type' => $account_type,
            'account_reason' => $account_reason,
            'account_important' => $account_important,
            'account_not_important' => $account_not_important,
        );
        return $this->make_call('v1/review/nps', 'POST', $params);
    }

    /**
     * @return string
     */
    private function getIp()
    {
        $address = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : null;
        if (is_string($address)) {
            if (strpos($address, ',') !== false) {
                $address = end(explode(',', $address));
            }
        }
        if (is_null($address)) {
            $address = $_SERVER['REMOTE_ADDR'];
        }
        return $address;
    }

    /**
     * @return array
     * @throws HostingerApiException
     */
    public function getTlds()
    {
        return $this->make_call('v1/domain/tlds', 'GET');
    }

    /**
     * @param string $cmd
     * @param string $method
     * @param array $post_fields
     * @return array
     * @throws HostingerApiException
     */
    private function make_call($cmd, $method = 'GET', $post_fields = array())
    {
        $result = $this->get_url($this->api_url.$cmd, $method, $post_fields, $this->username, $this->password);
        $result = json_decode($result, 1);
        if (isset($result['error']['message']) && !empty($result['error']['message'])) {
            throw new HostingerApiException($result['error']['message']);
        }
        return $result['result'];
    }

    /**
     * @param array $result
     * @return array
     */
    public function getValidationErrorsForResult($result) {
        if(isset($result['validation']) && !empty($result['validation'])) {
            return $result['validation'];
        }
        return array();
    }

    /**
     * @param array $params
     * @return array
     */
    public function registerDomainWithClient($params = array())
    {
        $defaultParams = array(
            'client' => array(
                'email'                    => '',
                'password'                 => '',
                'first_name'               => '',
                'country'                  => '',
                'client_ip'                => '',
                'last_name'                => '',
                'company'                  => '',
                'address_1'                => '',
                'address_2'                => '',
                'city'                     => '',
                'state'                    => '',
                'zip'                      => '',
                'phone_cc'                 => '',
                'phone'                    => '',
                'reseller_client_campaign' => false, // optional
            ),
            'order'  => array(
                'service'   => 'domain',
                'client_ip' => '',
                'domain'    => 'test-domain-name.lt',
                'years'     => 1,
                'action'    => 'register',
                'campaign'  => 'any name' // optional
            )
        );

        $post = array_replace_recursive($defaultParams, $params);

        return $this->make_call('v1/order/create-order-with-client', 'POST', $post);
    }


    /**
     * @param numeric $invoice_id
     * Generated Auto Login to Invoice link
     * @return array
     */
    public function getAutoLoginLinkByInvoiceId($invoice_id)
    {
        return $this->make_call('v1/client/get-manage-domain-link-by-invoice-id/'.$invoice_id, 'GET');
    }

    /**
     * @param string $url
     * @param string $method
     * @param array $post_fields
     * @param string $user
     * @param string $password
     * @param int $timeout
     * @return array
     * @throws HostingerApiException
     */
    private function get_url($url, $method, $post_fields = array(), $user = null, $password = null, $timeout = 30)
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)');
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_FAILONERROR, true);
        curl_setopt($ch, CURLOPT_AUTOREFERER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);

        if ($user && $password) {
            curl_setopt($ch, CURLOPT_USERPWD, "$user:$password");
        }

        switch (strtolower($method)) {
            case'delete' :
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
                break;
            case 'post' :
                $fields = http_build_query($post_fields, null, '&');
                curl_setopt($ch, CURLOPT_POST, 1);
                curl_setopt($ch, CURLOPT_POSTFIELDS, $fields);
                break;
            case 'get' :
                if(!empty($post_fields)) {
                    $url .= '?'.http_build_query($post_fields, null, '&');
                }
                break;
        }

        curl_setopt($ch, CURLOPT_URL, $url);

        $data = curl_exec($ch);
        if ($data === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new HostingerApiException("Request error: " . $error);
        }
        curl_close($ch);
        return $data;
    }
    


    
}
