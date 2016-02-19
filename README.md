# mod_dosdetector-fork

This is a fork of mod_dosdetector hosted at SourceForge.net (http://sourceforge.net/projects/moddosdetector/).

このソフトウェアはShinji Tanaka氏作のApacheモジュール`mod_dosdetector'の改造版です。オリジナルのmod_dosdetectorと同じライセンス（mod_dosdetector.cに記載）で公開されます。

この改造版についてのバグ報告や質問などは、 takayuki.3w@gmail.com 宛てに送ってください。

## 必要環境

バージョン1.1.0より、Apache 2.4以降が必要です。
Apache 2.2で使用したい場合は 1.0.0　を、
Apache 2.0には apache-2.0 ブランチを使用してください。

## mod_dosdetectorとは？

mod_dosdetectorは、DoS攻撃を検出するためのApacheモジュールです。
結果は環境変数に設定されるため、他のモジュールと連携することで柔軟な防御・回避アクションを実行すること可能です。

## fork版の主な改良点

- DoS攻撃チェックの対象としないアクセスを、環境変数で指定できます
- 不要なサブリクエストを省くことで、パフォーマンスを改善しています
- 共有メモリ処理を改善しています
- ロギング処理を改善しています（1.1.0以降）
- ロック処理を改善しています（1.1.0以降）

## インストール

```
sudo make install
```

apxsコマンドのパスが環境変数PATHに含まれていない場合、
makeに対する引数として設定してください。

```
sudo make PATH=/usr/sbin:$PATH install
```

### デバッグ用インストール

_DEBUGスイッチを有効にすることで、デバッグ用出力を有効にした状態でコンパイルできます。

```
DEF=-D_DEBUG make
sudo make install
```

### RPMの作成方法

```bash
cp mod_dosdetector-fork-x.y.z.tar.gz SOURCES/
cp mod_dosdetector-fork.spec SPECS/
rpmbuild -bb SPECS/mod_dosdetector-fork.spec
```

## 設定例

dosdetector-sample.conf を参照してください。
RPMからインストールした場合は、/etc/httpd/conf.d/dosdetector.conf にインストールされます。

## ディレクティブ・リファレンス

### DoSDetection
DoS攻撃チェックの有効/無効を切り替える。
（例:on）

### DoSPeriod
DoS攻撃チェックの基準となる時間間隔。
（例:5）

### DoSThreshold
DoS攻撃の疑いありと見なすアクセス数の閾値。
`DoSPeriod`秒以内に`DoSThreshold`回以上のアクセスがあると、環境変数SuspectDoSが設定される。
（例:20）

### DoSHardThreshold
より強いDoS攻撃の疑いありと見なすアクセス数の閾値。
`DoSPeriod`秒以内に`DoSHardThreshold`回以上のアクセスがあると、環境変数SuspectHardDoSが設定される。
（例:35）

### DoSBanPeriod
一度DoS攻撃の疑いがかかってから、チェックをリセットするまでの秒数。
（例:30）

### DoSTableSize
同時に追跡するIPアドレスの数。
（例:100）

### DoSShmemName
共有メモリの名前。
省略した場合は匿名の共有メモリが使用される。
匿名の共有メモリをサポートしていないプラットフォームでのみ、設定してください。


## 変更履歴

* 2016-02-18 Takayuki Miwa <takayuki.3w@gmail.com> - 1.1.0
	* Apache 2.4に対応
	* DoSShmemNameが設定されない場合、匿名の共有メモリを使用するように変更
	* mutex生成にutil_mutexを使用するように変更
	* コンパイル時にtmpnamによる警告が出るのを修正
	* ロギング処理を大幅に改善
	* コンパイル時にtmpnamにまつわる警告が出るのを修正
	* クリーンナップ処理を改善
	* エラー処理を改善

* 2009-08-17 Takayuki Miwa <takayuki.3w@gmail.com> - 1.0.0
	*  Initial release.
