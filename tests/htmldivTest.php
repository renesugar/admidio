<?php

use PHPUnit\Framework\TestCase;

class HtmlDivTest extends TestCase
{
    public function testHtmlDiv1()
    {
        $x = '<div id="test" class="c">hello</div>';
        $div = new HtmlDiv('test', 'c');
        $div->addHtml('hello');
        $this->assertEquals($x, $div->getHtmlElement());
    }
}
