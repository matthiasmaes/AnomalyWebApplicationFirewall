[![Code Health](https://landscape.io/github/matthiasmaes/AnomalyWebApplicationFirewall/master/landscape.svg?style=flat)](https://landscape.io/github/matthiasmaes/AnomalyWebApplicationFirewall/master)


# AnomalyWebApplicationFirewall
Development of an anomaly based web application firewall


## Options

| Option | Short | Description | Profiler | Unifier | Firewall
|:-------------|:-------------|:-----|:------|:------|:------|
| --ping | -p | Resolve domain names to ip address | ✔ | ✘ | ✘ |
| --bot | -b | Filter connections by crawlers | ✔ | ✘ | ✘ |
| --debug | -d | Display debug messages | ✔ | ✘ | ✘ |
| --log | -l | Specify path input log file | ✘ | ✔ | ✘ |
| --threads | -t | Maximum amount of threads | ✔ | ✔ | ✘ |
| --linesperthread | -x | Maximum lines per thread | ✔ | ✔ | ✘ |
| --format | -f | Format input log | ✘ | ✔ | ✘ |
| --mongo | -m | Define mongo collection input | ✔ | ✘ | ✘ |
| --unfamiliar | -u | Threshold for unfamiliar locations | ✘ | ✘ | ✔ |
| --ratio | -r | Threshold for location ratio | ✘ | ✘ | ✔ |
| --activity | -a| Threshold for activity/day| ✘ | ✘ | ✔ |



## Unifier
### Description
This script is used to unify access logs. The only prerequisites are that the nessesary parameters are logged and that all of the parameters are surrounded with double quotes. The outpout is saved in MongoDB which will be used as input for other scripts.

### Usage
`unifier -l [-t] [-x] [-f]`

### Example
`unifier -l input/log.txt`



## Profiler
### Description
This script is used to profile the unified script. It takes input from a given collection (MongoDB), output is also stored in MongoDB

### Usage
`profiler -m [-p] [-b] [-d] [-t] [-x]`

### Example
`profiler -m mongoCollection`



## Firewall
### Description
This script is used to run the web application firewall (simulated) based on the created profile

### Usage
`firewall [-u] [-r] [-a]`

### Example
`firewall -u 15 -r 10 -a 15`