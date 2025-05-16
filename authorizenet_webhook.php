<?php
class ControllerExtensionPaymentAuthorizenetWebhook extends Controller {
    public function index() {
        if ($this->request->server['REQUEST_METHOD'] !== 'POST') {
            http_response_code(405);
            echo json_encode(['error' => 'Method Not Allowed']);
            exit;
        }

        $webhook = file_get_contents('php://input');
        $response = json_decode(str_replace("\xEF\xBB\xBF", '', $webhook), true);

        if (!isset($response['webhookId'])) {
            http_response_code(400);
            echo json_encode(['error' => 'Invalid webhook payload']);
            exit;
        }

        if ($this->config->get('payment_authorizenet_ah_debug') == 1) {
            file_put_contents(DIR_LOGS . 'authnet_ah_webhook.log', print_r($response, true) . "\r\n\r\n", FILE_APPEND);
        }

        if ($response['payload']['responseCode'] == 1 || $response['payload']['responseCode'] == 4) {
            $this->load->model('checkout/order');
            $order = $this->model_checkout_order->getOrder($response['payload']['invoiceNumber']);

            if ($order) {
                if ($order['order_status_id'] == 0) {
                    $message = "Updated via WebHook\n";
                    $transaction = $response['transaction'];

                    if (isset($transaction['payment']['bankAccount']['routingNumber'])) {
                        // eCheck — clear unused CC fields to prevent notices
                        $transaction['payment']['creditCard']['cardNumber'] = '';
                        $transaction['payment']['creditCard']['expirationDate'] = '';
                        $transaction['authCode'] = '';
                        $transaction['cardCodeResponse'] = '';

                        $message .= 'Type: eCheck' . "\n";
                        $message .= 'AVS Response: ' . $transaction['AVSResponse'] . "\n";
                        $message .= 'Transaction ID: ' . $transaction['transId'] . "\n";
                        $message .= 'Routing Number: ' . $transaction['payment']['bankAccount']['routingNumber'] . "\n";
                        $message .= 'Account Number: ' . $transaction['payment']['bankAccount']['accountNumber'] . "\n";
                        $message .= 'Account Name: ' . $transaction['payment']['bankAccount']['nameOnAccount'] . "\n";
                        $message .= 'Account Type: ' . $transaction['payment']['bankAccount']['echeckType'] . "\n";
                    } else {
                        $message .= 'Type: CreditCard' . "\n";
                        $message .= 'Authorization Code: ' . $transaction['authCode'] . "\n";
                        $message .= 'AVS Response: ' . $transaction['AVSResponse'] . "\n";
                        $message .= 'Transaction ID: ' . $transaction['transId'] . "\n";
                        $message .= 'Card Number: ' . substr($transaction['payment']['creditCard']['cardNumber'], -4) . "\n";
                        $message .= 'Expiration: ' . $transaction['payment']['creditCard']['expirationDate'] . "\n";
                        $message .= 'Card Code Response: ' . $transaction['cardCodeResponse'] . "\n";
                    }

                    $status = $response['payload']['responseCode'] == 1 ?
                        $this->config->get('payment_authorizenet_ah_order_status_id') :
                        $this->config->get('payment_authorizenet_ah_hold_order_status_id');

                    $this->model_checkout_order->addOrderHistory($response['payload']['invoiceNumber'], $status, $message);
                } else {
                    if ($this->config->get('payment_authorizenet_ah_debug') == 1) {
                        file_put_contents(DIR_LOGS . 'authnet_ah_webhook.log', 'status: ignored' . "\r\n" . 'Reason: order with id "' . $response['payload']['invoiceNumber'] . '" has status id ' . $order['order_status_id'] . "\r\n\r\n---------------\r\n\r\n", FILE_APPEND);
                    }
                }

                // Transaction insertion check
                $x_login = $this->config->get('payment_authorizenet_ah_login');
                $x_tran_key = $this->config->get('payment_authorizenet_ah_key');

                $form_request = [
                    'getTransactionDetailsRequest' => [
                        'merchantAuthentication' => [
                            'name' => $x_login,
                            'transactionKey' => $x_tran_key,
                        ],
                        'transId' => $response['payload']['id']
                    ]
                ];

                $url = $this->config->get('payment_authorizenet_ah_server') == 'live'
                    ? 'https://api.authorize.net/xml/v1/request.api'
                    : 'https://apitest.authorize.net/xml/v1/request.api';

                $curl = curl_init($url);
                curl_setopt_array($curl, [
                    CURLOPT_PORT => 443,
                    CURLOPT_HEADER => 0,
                    CURLOPT_SSL_VERIFYPEER => 0,
                    CURLOPT_RETURNTRANSFER => 1,
                    CURLOPT_FORBID_REUSE => 1,
                    CURLOPT_FRESH_CONNECT => 1,
                    CURLOPT_POST => 1,
                    CURLOPT_CONNECTTIMEOUT => 10,
                    CURLOPT_TIMEOUT => 10,
                    CURLOPT_POSTFIELDS => json_encode($form_request)
                ]);

                $auth_response = json_decode(str_replace("\xEF\xBB\xBF", '', curl_exec($curl)), true);

                if (isset($auth_response['transaction'])) {
                    $trans = $auth_response['transaction'];
                    $order_id = (int)$order['order_id'];

                    $check = $this->db->query("SELECT * FROM `" . DB_PREFIX . "authnet_ah_transaction` WHERE `transaction_id` = '" . $this->db->escape($trans['transId']) . "' AND `order_id` = '" . $order_id . "'");

                    if (!$check->num_rows) {
                        $this->db->query("INSERT INTO `" . DB_PREFIX . "authnet_ah_transaction` SET
                            `transaction_id` = '" . $this->db->escape($trans['transId']) . "',
                            `order_id` = '" . $order_id . "',
                            `authorization_code` = '" . $this->db->escape($trans['authCode']) . "',
                            `avs_response` = '" . $this->db->escape($trans['AVSResponse']) . "',
                            `card_code_response` = '" . $this->db->escape($trans['cardCodeResponse']) . "',
                            `card_last_four` = '" . $this->db->escape(substr($trans['payment']['creditCard']['cardNumber'], -4)) . "',
                            `expiration_date` = '" . $this->db->escape($trans['payment']['creditCard']['expirationDate']) . "',
                            `amount` = '" . $this->db->escape($trans['authAmount']) . "',
                            `status` = '" . $this->db->escape($trans['transactionType']) . "'");
                    }
                }
            } else {
                if ($this->config->get('payment_authorizenet_ah_debug') == 1) {
                    file_put_contents(DIR_LOGS . 'authnet_ah_webhook.log', 'status: failed' . "\r\n" . 'Reason: order with id "' . $response['payload']['invoiceNumber'] . '" not found.' . "\r\n\r\n---------------\r\n\r\n", FILE_APPEND);
                }
            }
        } else {
            if ($this->config->get('payment_authorizenet_ah_debug') == 1) {
                file_put_contents(DIR_LOGS . 'authnet_ah_webhook.log', 'status: failed' . "\r\n" . 'Reason: response code is ' . $response['payload']['responseCode'] . "\r\n\r\n---------------\r\n\r\n", FILE_APPEND);
            }
        }

        http_response_code(200);
        echo json_encode(['status' => 'Processed']);
        exit;
    }
}
