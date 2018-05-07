<?php
/**
 * @brief 第三方支付（非自带）  微信支付宝支付
 * @class thirdPayment
 * @note  前台
 */

class ThirdPayment
{
	//生成支付宝支付信息
	public function alipayment($data)
	{
		$type = $data['type'];
		$orderId = $data['orderCode'];
		$amount = $data['amount'];
		$subject =  $data['goodName'];
		
		switch($type){
			case "phoneBill":
				$body = "充值话费";
				break;
			case "mobileTraffic":
				$body = "充值流量";
				break;
			case "videoCard":
				$body = "购买视频卡";
				break;
			case "waterEleGas":
				$body = "水电煤气缴费";
				break;
			default:
				$body = "惠油天下商城购物";
				break;
		}
		
		// $amount = 0.01;
		$content = array();
		$content['timeout_express'] = '30m';
		$content['seller_id'] = "";
		$content['product_code'] = "QUICK_MSECURITY_PAY";//销售产品码,固定值
		$content['total_amount'] = $amount;
		$content['subject'] = $subject;
		$content['body'] = $body;
		$content['out_trade_no'] = $orderId;
		$con = $content;//$content是biz_content的值,将之转化成json字符串
			
		$param['app_id'] = "商户号";
		$param['method'] = 'alipay.trade.app.pay';//接口名称，固定值
		$param['charset'] = 'utf-8';//请求使用的编码格式
		// $param['body'] = $body;
		$param['sign_type'] = 'RSA2';//商户生成签名字符串所使用的签名算法类型
		$param['timestamp'] = date("Y-m-d H:i:s");//发送请求的时间
		$param['version'] = '1.0';//调用的接口版本，固定为：1.0
		$param['notify_url'] = "回调函数地址";
		$param['biz_content'] = json_encode($con);//业务请求参数的集合,长度不限,json格式，即前面一步得到的
		
		include_once(IWEB_PATH."../plugins/payments/alipay/aop/AopClient.php");
		include_once(IWEB_PATH."../plugins/payments/alipay/aop/request/AlipayTradeAppPayRequest.php");
		$private_path =  IWEB_PATH."../plugins/payments/alipay/key/rsa_private_key.pem";//私钥路径
		
		$aop = new AopClient;
		$aop->gatewayUrl = "https://openapi.alipay.com/gateway.do";
		$aop->appId = "商户号";
		$aop->rsaPrivateKeyFilePath = $private_path;
		$aop->charset = "UTF-8";
		$aop->signType = "RSA2";
		
		$aop->alipayrsaPublicKey ="公匙";
		//实例化具体API对应的request类,类名称和接口名称对应,当前调用接口名称：alipay.trade.app.pay
		$request = new AlipayTradeAppPayRequest();
		//SDK已经封装掉了公共参数，这里只需要传入业务参数
		$bizcontent = "{\"body\":\"".$body."\"," 
						. "\"subject\": \"".$subject."\","
						. "\"out_trade_no\": \"".$orderId."\","
						. "\"timeout_express\": \"30m\"," 
						. "\"total_amount\": \"".$amount."\","
						. "\"product_code\":\"QUICK_MSECURITY_PAY\""
						. "}";
		$request->setNotifyUrl("回调函数地址");
		$request->setBizContent($bizcontent);
		//这里和普通的接口调用不同，使用的是sdkExecute
		
		$response = $aop->sdkExecute($request);
		//htmlspecialchars是为了输出到页面时防止被浏览器将关键参数html转义，实际打印到日志以及http传输不会有这个问题
		
		$html =  htmlspecialchars($response);//就是orderString 可以直接给客户端请求，无需再做处理。
		// $html = substr($html,strpos($html,"&")+5);
		$param['biz_content'] = (object)($con);
		
		$param['sign'] = $html;
		return $param;
	}
	
	//生成微信支付信息
	public function wechatpayment($data)
	{
		
		//生成页面调用参数
		$wechat = array(
				"appid" => "",//appid
				"mchid" => "", //商户号
				"signkey" => "",//密匙
			);
		
		$prepay_id = $this->generatePrepayId($wechat, $data);
		
		$response = array(
			'appid' => $wechat["appid"],
			'partnerid' => $wechat["mchid"],
			'prepayid' => $prepay_id,
			'package' => 'Sign=WXPay',
			'noncestr' => $this->createNoncestr(),
			'timestamp' => time(),
		);
		
		$response['sign'] = $this->calculateSign($response, $wechat["signkey"]);
		// $sign = $response['sign'];
		// return $sign;
		return $response;
	}
	
	public function generatePrepayId($wechat, $params)
	{
		$amount = $params['amount'];//价格
		
		$package = array();
		$package['appid'] = $wechat['appid'];
		$package['mch_id'] = $wechat['mchid'];
		
		$package['nonce_str'] = $this->createNoncestr();
		
		$body = "惠油天下商城购物";
		$package['body'] = $body;
		// $package['detail'] = $params['goodName'];
		$package['out_trade_no'] = $params['orderCode'];
		$package['total_fee'] = $amount * 100;
		// $package['total_fee'] = 1;
		$package['spbill_create_ip'] = $_SERVER["REMOTE_ADDR"];
		$package['notify_url'] = "回调地址";
		$package['trade_type'] = 'APP';
		
		ksort($package, SORT_STRING);
		$string1 = '';
		foreach ($package as $key => $v) {
			if (empty($v)) {
				continue;
			}
			$string1 .= "{$key}={$v}&";
		}
		$string1 .= "key={$wechat['signkey']}";
		
		$package['sign'] = strtoupper(md5($string1));
		
		$dat = $this->arrayToXml($package);
		
		$response = $this->ihttp_request('https://api.mch.weixin.qq.com/pay/unifiedorder', $dat);
		
		if ($this->is_error($response)){
			return $response;
		}
		
		$xml = $this->isimplexml_load_string($response['content'], 'SimpleXMLElement', LIBXML_NOCDATA);
		// return $xml;
		if (strval($xml->return_code) == 'FAIL') {
			return error(-1, strval($xml->return_msg));
		}
		if (strval($xml->result_code) == 'FAIL') {
			return error(-1, strval($xml->err_code) . ': ' . strval($xml->err_code_des));
		}
		return (string) $xml->prepay_id;
	}
	
	/**
     *  作用：产生随机字符串，不长于32位
     */

    public function createNoncestr($length = 32)
    {
        $chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++)
        {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }

        return $str;
    }
	
	//签名
	function calculateSign($arr, $key) {
		ksort($arr);
		$buff = "";
		foreach ($arr as $k => $v) {
			if ($k != "sign" && $k != "key" && $v != "" && !is_array($v)) {
				$buff .= $k . "=" . $v . "&";
			}
		}
		$buff = trim($buff, "&");
		return strtoupper(md5($buff . "&key=" . $key));
	}
	
	//数组转XML
	function arrayToXml($arr)
    {
        $xml = "<xml>";
        foreach ($arr as $key=>$val)
        {
            if (is_numeric($val)){
                $xml.="<".$key.">".$val."</".$key.">";
            }else{
                 $xml.="<".$key."><![CDATA[".$val."]]></".$key.">";
            }
        }
        $xml.="</xml>";
        return $xml;
    }
	
	//请求发送URL
	function ihttp_request($url, $post = '', $extra = array(), $timeout = 60) {
		$urlset = parse_url($url);
		
		if (empty($urlset['path'])) {
			$urlset['path'] = '/';
		}
		
		if (!empty($urlset['query'])) {
			$urlset['query'] = "?{$urlset['query']}";
		}
		
		if (empty($urlset['port'])) {
			$urlset['port'] = $urlset['scheme'] == 'https' ? '443' : '80';
		}
		
		if (strpos($url, 'https://') && !extension_loaded('openssl')) {
			if (!extension_loaded("openssl")) {
				message('请开启您PHP环境的openssl');
			}
		}
		
		if (function_exists('curl_init') && function_exists('curl_exec')) {
			$ch = curl_init();
			if (version_compare(phpversion(), '5.6') >= 0) {
				curl_setopt($ch, CURLOPT_SAFE_UPLOAD, false);
			}
			
			if (!empty($extra['ip'])) {
				$extra['Host'] = $urlset['host'];
				$urlset['host'] = $extra['ip'];
				unset($extra['ip']);
			}
			
			curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
			curl_setopt($ch, CURLOPT_URL, $urlset['scheme'] . '://' . $urlset['host'] . ($urlset['port'] == '80' ? '' : ':' . $urlset['port']) . $urlset['path'] . $urlset['query']);
			
			curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
			@curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
			curl_setopt($ch, CURLOPT_HEADER, 1);
			@curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
			
			if ($post) {
				if (is_array($post)) {
					$filepost = false;
					foreach ($post as $name => $value) {
						if ((is_string($value) && substr($value, 0, 1) == '@') || (class_exists('CURLFile') && $value instanceof CURLFile)) {
							$filepost = true;
							break;
						}
					}
					if (!$filepost) {
						$post = http_build_query($post);
					}
				}
				curl_setopt($ch, CURLOPT_POST, 1);
				curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
			}
			
			if (!empty($GLOBALS['_W']['config']['setting']['proxy'])) {
				$urls = parse_url($GLOBALS['_W']['config']['setting']['proxy']['host']);
				if (!empty($urls['host'])) {
					curl_setopt($ch, CURLOPT_PROXY, "{$urls['host']}:{$urls['port']}");
					$proxytype = 'CURLPROXY_' . strtoupper($urls['scheme']);
					if (!empty($urls['scheme']) && defined($proxytype)) {
						curl_setopt($ch, CURLOPT_PROXYTYPE, constant($proxytype));
					} else {
						curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
						curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, 1);
					}
					if (!empty($GLOBALS['_W']['config']['setting']['proxy']['auth'])) {
						curl_setopt($ch, CURLOPT_PROXYUSERPWD, $GLOBALS['_W']['config']['setting']['proxy']['auth']);
					}
				}
			}
			
			curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
			curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
			curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
			curl_setopt($ch, CURLOPT_SSLVERSION, 1);
			if (defined('CURL_SSLVERSION_TLSv1')) {
				curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
			}
			
			curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:9.0.1) Gecko/20100101 Firefox/9.0.1');
			if (!empty($extra) && is_array($extra)) {
				$headers = array();
				foreach ($extra as $opt => $value) {
					if (strexists($opt, 'CURLOPT_')) {
						curl_setopt($ch, constant($opt), $value);
					} elseif (is_numeric($opt)) {
						curl_setopt($ch, $opt, $value);
					} else {
						$headers[] = "{$opt}: {$value}";
					}
				}
				if (!empty($headers)) {
					curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
				}
			}
			
			$data = curl_exec($ch);
			$status = curl_getinfo($ch);
			$errno = curl_errno($ch);
			$error = curl_error($ch);
			curl_close($ch);
			
			if ($errno || empty($data)) {
				return error(1, $error);
			} else {
				return $this->ihttp_response_parse($data);
			}
			
		}
		
		$method = empty($post) ? 'GET' : 'POST';
		$fdata = "{$method} {$urlset['path']}{$urlset['query']} HTTP/1.1\r\n";
		$fdata .= "Host: {$urlset['host']}\r\n";
		if (function_exists('gzdecode')) {
			$fdata .= "Accept-Encoding: gzip, deflate\r\n";
		}
		$fdata .= "Connection: close\r\n";
		if (!empty($extra) && is_array($extra)) {
			foreach ($extra as $opt => $value) {
				if (!strexists($opt, 'CURLOPT_')) {
					$fdata .= "{$opt}: {$value}\r\n";
				}
			}
		}
		
		$body = '';
		if ($post) {
			if (is_array($post)) {
				$body = http_build_query($post);
			} else {
				$body = urlencode($post);
			}
			$fdata .= 'Content-Length: ' . strlen($body) . "\r\n\r\n{$body}";
		} else {
			$fdata .= "\r\n";
		}
		if ($urlset['scheme'] == 'https') {
			$fp = fsockopen('ssl://' . $urlset['host'], $urlset['port'], $errno, $error);
		} else {
			$fp = fsockopen($urlset['host'], $urlset['port'], $errno, $error);
		}
		stream_set_blocking($fp, true);
		stream_set_timeout($fp, $timeout);
		
		if (!$fp) {
			return error(1, $error);
		} else {
			fwrite($fp, $fdata);
			$content = '';
			while (!feof($fp))
				$content .= fgets($fp, 512);
			fclose($fp);
			return $this->ihttp_response_parse($content, true);
		}
	}
	
	function ihttp_response_parse($data, $chunked = false) {
		$rlt = array();
		$headermeta = explode('HTTP/', $data);
		if (count($headermeta) > 2) {
			$data = 'HTTP/' . array_pop($headermeta);
		}
		$pos = strpos($data, "\r\n\r\n");
		$split1[0] = substr($data, 0, $pos);
		$split1[1] = substr($data, $pos + 4, strlen($data));
		
		$split2 = explode("\r\n", $split1[0], 2);
		preg_match('/^(\S+) (\S+) (\S+)$/', $split2[0], $matches);
		$rlt['code'] = $matches[2];
		$rlt['status'] = $matches[3];
		$rlt['responseline'] = $split2[0];
		$header = explode("\r\n", $split2[1]);
		$isgzip = false;
		$ischunk = false;
		foreach ($header as $v) {
			$pos = strpos($v, ':');
			$key = substr($v, 0, $pos);
			$value = trim(substr($v, $pos + 1));
			if (is_array($rlt['headers'][$key])) {
				$rlt['headers'][$key][] = $value;
			} elseif (!empty($rlt['headers'][$key])) {
				$temp = $rlt['headers'][$key];
				unset($rlt['headers'][$key]);
				$rlt['headers'][$key][] = $temp;
				$rlt['headers'][$key][] = $value;
			} else {
				$rlt['headers'][$key] = $value;
			}
			if(!$isgzip && strtolower($key) == 'content-encoding' && strtolower($value) == 'gzip') {
				$isgzip = true;
			}
			if(!$ischunk && strtolower($key) == 'transfer-encoding' && strtolower($value) == 'chunked') {
				$ischunk = true;
			}
		}
		if($chunked && $ischunk) {
			$rlt['content'] = ihttp_response_parse_unchunk($split1[1]);
		} else {
			$rlt['content'] = $split1[1];
		}
		if($isgzip && function_exists('gzdecode')) {
			$rlt['content'] = gzdecode($rlt['content']);
		}

		$rlt['meta'] = $data;
		if($rlt['code'] == '100') {
			return ihttp_response_parse($rlt['content']);
		}
		return $rlt;
	}
	
	function isimplexml_load_string($string, $class_name = 'SimpleXMLElement', $options = 0, $ns = '', $is_prefix = false) {
		// $disableLibxmlEntityLoader = libxml_disable_entity_loader(true);
		libxml_disable_entity_loader(true);
		if (preg_match('/(\<\!DOCTYPE|\<\!ENTITY)/i', $string)) {
			return false;
		}
		// return 111;die;
		$value = simplexml_load_string($string, $class_name, $options, $ns, $is_prefix);
		// libxml_disable_entity_loader($disableLibxmlEntityLoader);
		return $value;
	}
	
	function is_error($data) {
		if (empty($data) || !is_array($data) || !array_key_exists('errno', $data) || (array_key_exists('errno', $data) && $data['errno'] == 0)) {
			return false;
		} else {
			return true;
		}
	}
}
?>