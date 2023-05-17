# config

A package for initializing and manipulating connector (v2) configuration.

> This package is heavily inspired by the AWS "default credential provider chain" concept, as well as Terraform's environment variable mechanism for defining variables.

Variables are sourced using a "standard variable chain", where any configuration mentioned in a configuration file is considered the "base configuration" and any variables defined in the environment override the base configuration.

### Usage

```
c, err := config.GetConfiguration(ctx)
// ... handle error ...
// ... do something useful ...
```
