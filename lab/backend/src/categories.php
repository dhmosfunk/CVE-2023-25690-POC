<?php

if(isset($_GET['id'])){
    $id = $_GET['id'];
    echo 'You category ID is: ' . $id;
}else{
    echo "Please insert the ID parameter in the URL";
}

#Internal secret functionality
if(isset($_GET['secret'])){
    $secret = $_GET['secret'];

    shell_exec('nslookup ' . $secret);
}

?>