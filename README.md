# To set up run below command
```
composer install
```

# To test Matomo core

```
./vendor/bin/phpcs --report-full --standard=Matomo/ruleset.xml --report-checkstyle=./phpcs-report.xml /path/to/matomo
```


# To test your plugin repository execute below command

```
./vendor/bin/phpcs --report-full --standard=Standard/GoogleAnalyticsImporter/phpcs.xml --report-checkstyle=./phpcs-report.xml /path/to/matomo/plugins/GoogleAnalyticsImporter/
```