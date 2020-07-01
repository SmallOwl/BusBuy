<?php
ignore_user_abort(true);
set_time_limit(0);

//Часть с бд(смотреть ниже)
    $host = 'localhost'; // адрес сервера 
    $database = 'Globus'; // имя базы данных
    $user = 'smallowl'; // имя пользователя
    $password = 'uliasha'; // пароль
    $link = mysqli_connect($host, $user, $password, $database) or die("Ошибка " . mysqli_error($link));//Подключение к бд
    mysqli_set_charset($link,"utf8");

//Часть с отправкой почты
require 'PHPMailer.php';
require 'SMTP.php';
require 'Exception.php';

//Подключение и настройка PHPMailer
$mail = new PHPMailer\PHPMailer\PHPMailer();
$mail->IsSMTP();
$mail->Host       = "smtp.gmail.com";
$mail->SMTPDebug  = 0;
$mail->SMTPAuth   = true;
$mail->SMTPSecure = "ssl";
$mail->Port       = 465;
$mail->Priority    = 3;
$mail->CharSet     = 'UTF-8';
$mail->Encoding    = '8bit';
$mail->Subject     = "Тест php mailer";
$mail->ContentType = "text/html; charset=utf-8\r\n";
$mail->Username   = "globus.mail.send@gmail.com";
$mail->Password   = "send_mai1";
$mail->setFrom('globus.mail.send@gmail.com', 'GLOBUS');
$mail->isHTML(true);
$mail->WordWrap = 50;
$mail->AddAddress("maks.sony.ru@gmail.com");

//Часть с сокетами(смотреть ниже)
$socket = stream_socket_server("tcp://localhost:5151", $errno, $errstr);
if (!$socket) {
    die("$errstr ($errno)\n");
} 
$connects = array();
while (true) {
    //формируем массив прослушиваемых сокетов:
    $read = $connects;
    $read []= $socket;
    $write = $except = null;
    if (!stream_select($read, $write, $except, null)) {//ожидаем сокеты доступные для чтения (без таймаута)
        break;
    }
    if (in_array($socket, $read)) {//есть новое соединение
        //принимаем новое соединение и производим рукопожатие:
        if (($connect = stream_socket_accept($socket, -1)) && $info = handshake($connect)) {
            $connects[] = $connect;//добавляем его в список необходимых для обработки
            onOpen($connect, $info);//вызываем пользовательский сценарий
        }
        unset($read[ array_search($socket, $read) ]);
    }
    foreach($read as $connect) {//обрабатываем все соединения
        $data = fread($connect, 100000);
        if (!$data) { //соединение было закрыто
            fclose($connect);
            unset($connects[ array_search($connect, $connects) ]);
            onClose($connect);//вызываем пользовательский сценарий
            continue;
        }
        onMessage($connect, $data,$info);//вызываем пользовательский сценарий
    }
}
fclose($server);

function handshake($connect) {
    $info = array();
    $line = fgets($connect);
    $header = explode(' ', $line);
    $info['method'] = $header[0];
    $info['uri'] = $header[1];
    //считываем заголовки из соединения
    while ($line = rtrim(fgets($connect))) {
        if (preg_match('/\A(\S+): (.*)\z/', $line, $matches)) {
            $info[$matches[1]] = $matches[2];
        } else {
            break;
        }
    }
    $address = explode(':', stream_socket_get_name($connect, true)); //получаем адрес клиента
    $info['ip'] = $address[0];
    $info['port'] = $address[1];
    if (empty($info['Sec-WebSocket-Key'])) {
        return false;
    }
    //отправляем заголовок согласно протоколу вебсокета
    $SecWebSocketAccept = base64_encode(pack('H*', sha1($info['Sec-WebSocket-Key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
    $upgrade = "HTTP/1.1 101 Web Socket Protocol Handshake\r\n" .
        "Upgrade: websocket\r\n" .
        "Connection: Upgrade\r\n" .
        "Sec-WebSocket-Accept:$SecWebSocketAccept\r\n\r\n";
    fwrite($connect, $upgrade);
    return $info;
}

function encode($payload, $type = 'text', $masked = false){
    $frameHead = array();
    $payloadLength = strlen($payload);
    switch ($type) {
        case 'text':
            $frameHead[0] = 129;
            break;
        case 'close':
            $frameHead[0] = 136;
            break;
        case 'ping':
            $frameHead[0] = 137;
            break;
        case 'pong':
            $frameHead[0] = 138;
            break;
    }
    if ($payloadLength > 65535) {
        $payloadLengthBin = str_split(sprintf('%064b', $payloadLength), 8);
        $frameHead[1] = ($masked === true) ? 255 : 127;
        for ($i = 0; $i < 8; $i++) {
            $frameHead[$i + 2] = bindec($payloadLengthBin[$i]);
        }
        if ($frameHead[2] > 127) {
            return array('type' => '', 'payload' => '', 'error' => 'frame too large (1004)');
        }
    } elseif ($payloadLength > 125) {
        $payloadLengthBin = str_split(sprintf('%016b', $payloadLength), 8);
        $frameHead[1] = ($masked === true) ? 254 : 126;
        $frameHead[2] = bindec($payloadLengthBin[0]);
        $frameHead[3] = bindec($payloadLengthBin[1]);
    } else {
        $frameHead[1] = ($masked === true) ? $payloadLength + 128 : $payloadLength;
    }
    // convert frame-head to string:
    foreach (array_keys($frameHead) as $i) {
        $frameHead[$i] = chr($frameHead[$i]);
    }
    if ($masked === true) {
        // generate a random mask:
        $mask = array();
        for ($i = 0; $i < 4; $i++) {
            $mask[$i] = chr(rand(0, 255));
        }
        $frameHead = array_merge($frameHead, $mask);
    }
    $frame = implode('', $frameHead);
    // append payload to frame:
    for ($i = 0; $i < $payloadLength; $i++) {
        $frame .= ($masked === true) ? $payload[$i] ^ $mask[$i % 4] : $payload[$i];
    }
    return $frame;
}

function decode($data){
    $unmaskedPayload = '';
    $decodedData = array();
    // estimate frame type:
    $firstByteBinary = sprintf('%08b', ord($data[0]));
    $secondByteBinary = sprintf('%08b', ord($data[1]));
    $opcode = bindec(substr($firstByteBinary, 4, 4));
    $isMasked = ($secondByteBinary[0] == '1') ? true : false;
    $payloadLength = ord($data[1]) & 127;
    // unmasked frame is received:
    if (!$isMasked) {
        return array('type' => '', 'payload' => '', 'error' => 'protocol error (1002)');
    }
    switch ($opcode) {
        // text frame:
        case 1:
            $decodedData['type'] = 'text';
            break;
        case 2:
            $decodedData['type'] = 'binary';
            break;
        // connection close frame:
        case 8:
            $decodedData['type'] = 'close';
            break;
        // ping frame:
        case 9:
            $decodedData['type'] = 'ping';
            break;
        // pong frame:
        case 10:
            $decodedData['type'] = 'pong';
            break;
        default:
            return array('type' => '', 'payload' => '', 'error' => 'unknown opcode (1003)');
    }
    if ($payloadLength === 126) {
        $mask = substr($data, 4, 4);
        $payloadOffset = 8;
        $dataLength = bindec(sprintf('%08b', ord($data[2])) . sprintf('%08b', ord($data[3]))) + $payloadOffset;
    } elseif ($payloadLength === 127) {
        $mask = substr($data, 10, 4);
        $payloadOffset = 14;
        $tmp = '';
        for ($i = 0; $i < 8; $i++) {
            $tmp .= sprintf('%08b', ord($data[$i + 2]));
        }
        $dataLength = bindec($tmp) + $payloadOffset;
        unset($tmp);
    } else {
        $mask = substr($data, 2, 4);
        $payloadOffset = 6;
        $dataLength = $payloadLength + $payloadOffset;
    }
    /**
     * We have to check for large frames here. socket_recv cuts at 1024 bytes
     * so if websocket-frame is > 1024 bytes we have to wait until whole
     * data is transferd.
     */
    if (strlen($data) < $dataLength) {
        return false;
    }
    if ($isMasked) {
        for ($i = $payloadOffset; $i < $dataLength; $i++) {
            $j = $i - $payloadOffset;
            if (isset($data[$i])) {
                $unmaskedPayload .= $data[$i] ^ $mask[$j % 4];
            }
        }
        $decodedData['payload'] = $unmaskedPayload;
    } else {
        $payloadOffset = $payloadOffset - 4;
        $decodedData['payload'] = substr($data, $payloadOffset);
    }
    return $decodedData;
} 

//пользовательские сценарии:
function onOpen($connect, $info) {
}

function onClose($connect) {
}

function onMessage($connect, $data,$info) {
    global $link;
    $to_send["type"] = json_decode(decode($data)["payload"],true)["type"];
    switch (json_decode(decode($data)["payload"],true)["type"]) {
        case "get_autocomplete":
            $query = "SELECT DISTINCT `text_city` FROM `city`";
            $result = mysqli_query($link, $query);
            while ($tablerows = mysqli_fetch_row($result)){
                $to_send["data"][$tablerows[0]] = null;
            }
            fwrite($connect, encode(json_encode($to_send,JSON_UNESCAPED_UNICODE)));
            break;
        case "get_buses":
            $query = "SELECT id_flight,text_route,route_date,time_in_way,cost,name_ferryman FROM `flight` INNER JOIN route ON route.id_route = flight.id_route INNER JOIN date ON date.id_date = flight.id_date INNER JOIN `ferryman` ON ferryman.id_ferryman = flight.id_ferryman WHERE (flight.id_route IN (SELECT id_route FROM `route` WHERE text_route LIKE (SELECT CONCAT((SELECT CONCAT((SELECT CONCAT((SELECT CONCAT('%',(SELECT id_city FROM `city` WHERE text_city = ?))),'%')),(SELECT id_city FROM `city` WHERE text_city = ?))),'%')))) AND (flight.id_date IN (SELECT IF(date.is_unique,(SELECT date.id_date FROM `date` WHERE date.week LIKE (SELECT CONCAT((SELECT CONCAT('%',?)),'%'))),(SELECT date.id_date FROM `date` WHERE date.day = ?)) FROM `date`))";
            $stmt = mysqli_stmt_init($link);
            mysqli_stmt_prepare($stmt, $query);
            mysqli_stmt_bind_param($stmt, "ssss", $a,$b,$c,$d);
            $a = json_decode(decode($data)["payload"],true)["data"]["from"];
            $b = json_decode(decode($data)["payload"],true)["data"]["to"];
            $c = json_decode(decode($data)["payload"],true)["data"]["day"];
            $d = json_decode(decode($data)["payload"],true)["data"]["when"];
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $i = 0;
            while($row = mysqli_fetch_array($result, MYSQLI_NUM)){
                $to_send["data"][$i]["id"] = $row[0];
                $to_send["data"][$i]["time_in_way"] = $row[3];
                $to_send["data"][$i]["cost"] = $row[4];
                $to_send["data"][$i]["ferryman"] = $row[5];
                $to_send["data"][$i]["date_from"] = json_decode(decode($data)["payload"],true)["data"]["when"];
                $date = explode(",",$row[2]);
                $way = explode(",",$row[1]);
                $j = 0;
                foreach($way as $value) {
                    $get_city = explode(".",$value);
                    $query_in = "SELECT text_city,text_station FROM `city` INNER JOIN `station` ON station.id_city = city.id_city WHERE (city.id_city = ?) AND (station.id_station = ?)";
                    $stmt_in = mysqli_stmt_init($link);
                    mysqli_stmt_prepare($stmt_in, $query_in);
                    mysqli_stmt_bind_param($stmt_in, "ii", $a,$b);
                    $a = $get_city[0];
                    $b = $get_city[1];
                    mysqli_stmt_execute($stmt_in);
                    $result_in = mysqli_stmt_get_result($stmt_in);
                    $row_in = mysqli_fetch_array($result_in, MYSQLI_NUM);
                    $to_send["data"][$i]["city"][$j] = $row_in[0];
                    $to_send["data"][$i]["station"][$j] = $row_in[1];
                    $to_send["data"][$i]["time"][$j] = $date[$j];
                    mysqli_stmt_close($stmt_in);
                    $j = $j+1;
                }
                $i = $i+1;
            }
            mysqli_stmt_close($stmt);
            fwrite($connect, encode(json_encode($to_send,JSON_UNESCAPED_UNICODE)));
            break;
        case "buy_bilet":
            $query = "INSERT INTO `order_bilet`(name,surname,count,telephone,id_flight) VALUES(?,?,?,?,?)";
            $stmt = mysqli_stmt_init($link);
            mysqli_stmt_prepare($stmt, $query);
            mysqli_stmt_bind_param($stmt, "ssisi", $a,$b,$c,$d,$e);
            $a = json_decode(decode($data)["payload"],true)["data"]["name"];
            $b = json_decode(decode($data)["payload"],true)["data"]["surname"];
            $c = json_decode(decode($data)["payload"],true)["data"]["count"];
            $d = json_decode(decode($data)["payload"],true)["data"]["telephone"];
            $e = json_decode(decode($data)["payload"],true)["data"]["id_flight"];
            mysqli_stmt_execute($stmt);
            $query = "SELECT text_route,route_date FROM `route` INNER JOIN `date` WHERE (id_route = (SELECT id_route FROM `flight` WHERE id_flight = 1) AND id_date = (SELECT id_date FROM `flight` WHERE id_flight = ?))";
            $stmt = mysqli_stmt_init($link);
            mysqli_stmt_prepare($stmt, $query);
            mysqli_stmt_bind_param($stmt, "i", $a);
            $a = json_decode(decode($data)["payload"],true)["data"]["id_flight"];
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            $row = mysqli_fetch_array($result, MYSQLI_NUM);
            $b = explode(",",$row[0]);
            $c = explode('.',$b[0]);
            mysqli_stmt_close($stmt);
            $query_first = "SELECT text_city,text_station  FROM `city` INNER JOIN `station` WHERE (city.id_city = ?) AND (station.id_station = ?)";
            $stmt_first = mysqli_stmt_init($link);
            mysqli_stmt_prepare($stmt_first, $query_first);
            mysqli_stmt_bind_param($stmt_first, "ii", $a,$d);
            $a = $c[0];
            $d = $c[1];
            mysqli_stmt_execute($stmt_first);
            $result_first = mysqli_stmt_get_result($stmt_first);
            $row_first = mysqli_fetch_array($result_first, MYSQLI_NUM);
            $c = explode('.',$b[count($b)-1]);
            mysqli_stmt_close($stmt_first);
            $query_second = "SELECT text_city,text_station  FROM `city` INNER JOIN `station` WHERE (city.id_city = ?) AND (station.id_station = ?)";
            $stmt_second = mysqli_stmt_init($link);
            mysqli_stmt_prepare($stmt_second, $query_second);
            mysqli_stmt_bind_param($stmt_second, "ii", $a,$b);
            $a = $c[0];
            $b = $c[1];
            mysqli_stmt_execute($stmt_second);
            $result_second = mysqli_stmt_get_result($stmt_second);
            $row_second = mysqli_fetch_array($result_second, MYSQLI_NUM);
            $e = explode(",",$row[1]);
            mysqli_stmt_close($stmt_second);
            global $mail;
            $mail->Body = json_decode(decode($data)["payload"],true)["data"]["name"]."---".json_decode(decode($data)["payload"],true)["data"]["surname"]."---".json_decode(decode($data)["payload"],true)["data"]["count"]."---".json_decode(decode($data)["payload"],true)["data"]["telephone"]."</br>".$row_first[0]." ".$row_first[1]."---".$row_second[0]." ".$row_second[1]."</br>".$e[0]."---".$e[count($e)-1];
            $mail->send();
            $to_send["data"]["done"] = true;
            fwrite($connect, encode(json_encode($to_send,JSON_UNESCAPED_UNICODE)));
            break;
        }
}    

?>