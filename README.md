# go-checkiptools

[![Build Status](https://travis-ci.org/johnsonz/go-checkiptools.svg?branch=master)](https://travis-ci.org/johnsonz/go-checkiptools) [![GPLv3 License](https://img.shields.io/badge/license-GPLv3-blue.svg)](https://github.com/johnsonz/go-checkiptools/blob/master/LICENSE)
============

使用Go语言编写，在性能上会比Python版的有一些提升，功能参考了[checkgoogleip](https://github.com/moonshawdo/checkgoogleip)、[checkiptools](https://github.com/xyuanmu/checkiptools)、[gogotester](https://github.com/azzvx/gogotester)感谢大家！

自带实用小工具，扫描完成后会自动将ip写入到gae.json或gae.user.json，可以根据条件提取扫描出的ip，并可在goagent和goproxy ip格式之间相互转换。在扫描完成后会自动测试带宽（但仅限gws的ip）。

## 下载地址
https://github.com/johnsonz/go-checkiptools/releases

## 配置说明

`"concurrency":10000` 并发线程数，可根据自己的硬件配置调整

`"delay":1200` 扫描完成后，提取所有小于等于该延迟的ip

`"sort_tmpokfile":true` 扫描完成后，是否对ip_tmpok.txt中的ip根据延迟进行排序

`"check_last_okip":true` 是否检查上一次的ok ip

`"check_bandwidth":true` 扫描完成后，是否测试带宽（仅限gws的ip）

`"bandwidth_concurrency":10` 测试带宽的并发线程数，可根据自己的网络环境调整

`"write_to_goproxy":false` 扫描完成后是否将ip自动写入到gae.json或gae.user.json，默认为false，不写入

`"goproxy_path":""` goproxy目录，请注意目录分隔符，windows下需用`\`转义
