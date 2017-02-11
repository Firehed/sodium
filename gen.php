<?php

$output = array_map('parse', include 'src/functionlist.php');

$tpl = <<<PHP
<?php

namespace Sodium;

if (!function_exists('Sodium\add')) {
PHP;
echo $tpl;

foreach ($output as $code) {
    echo $code;
}

echo "\n}";

function parse($func) {
    $ref = new ReflectionFunction($func);

    $ret = $ref->getReturnType();

    $params = array_map('parseParameter', $ref->getParameters());

    $f = new Func();
    $f->name = substr($func, 7);
    $f->internal_name = '\sodium_' . $f->name;
    $f->return = $ret ? $ret->__toString() : 'IDK';
    $f->args = $params;

    return $f->renderCode();
}

function parseParameter(ReflectionParameter $param): array {
    $default = '';
    if ($param->isOptional()) {
//_        $default = ' = '.$param->getDefaultValue();
    }

    if ($type = $param->getType()) {
        $type = (string)$type;
    }

    $dollarName = '$'.$param->getName();

    $sig = trim(sprintf('%s $%s%s',
        $type,
        $param->getName(),
        $default));
    return [
        'signature' => $sig,
        'name' => $dollarName,
    ];
}


class Func {
    public $name = '';
    public $args = [];
    public $return = '';
    public $internal_name = '';

    private function renderDocblock(int $spaces = 4): string {
        $desc = 'What this function does.';
        $longest = array_reduce($this->args, function($car, $info) {
            $len = strlen($info['name']);
            return $car > $len ? $car : $len;
        }, 0);

        $block = [];
        $block[] = $desc;
        $block[] = '';

        $params = array_map(function($info) use ($longest) {
            return sprintf("@param %s %-{$longest}s %s",
                'TYPE',
                $info['name'],
                'desc');
        }, $this->args);
        $block += $params;

        $ret = $this->return;
        if ($ret) {
            $block[] = '';
            $block[] = sprintf('@return %s', $ret);
        }

        $lines = array_map(function ($line) { return ' * '.$line; }, $block);
        array_unshift($lines, '/**');
        $lines[] = ' */';

        return implode("\n", $lines);
    }

    public function renderCode(int $spaces = 4): string {
        $unindented = $this->renderFunction();
        $indent = str_repeat(' ', $spaces);
        return implode("\n",
            array_map(function($line) use ($indent) {
                return rtrim($indent.$line);
            }, explode("\n", $unindented)));
    }

    private function renderFunction(): string {
        $internal_args = array_map(function($info) {
            return $info['name'];
        }, $this->args);
        $internal_args = implode(', ', $internal_args);

        $sig_args = implode(', ', array_map(function($info) {
            return $info['signature'];
        }, $this->args));

        $return = $this->return ? ': '.$this->return : '';
        $docblock = $this->renderDocblock();
        return <<<PHP


{$docblock}
function {$this->name}({$sig_args}){$return}
{
    return {$this->internal_name}({$internal_args});
}
PHP;
    }
}
