# Cert-services

(The project is under development and has many limitations, and many improvements and refactoring to be done. Feel free to contribute :))

Spring Boot project that provides digital certificates and PKI services and utilities via REST and Web interface.
Actually, it's main purposes are: 

- provide a testing PKI that can be easily deployed and managed.
- digital certificate utilities services.
- provide APIs to easily integrate those services in testing code.   

## Developing

I use Eclipse STS (Spring Tool Suite) for developing this project, if you choose to do so it would be enough to import the project as a Maven project. You may could have to execute a feel more steps on a raw Eclipse installation, but start importing as a Maven project and in a couple minutes you should have the project good to go.

## Running

In STS: Run As -> Spring Boot Project
Or generate an executable jar (/target) through Run As -> Maven install and double click it to run.

Access http://localhost:8080 and you should get to the main web interface. There's still too much hardcoded implementation, so feel free to change the default port or address, but you will have a little bit of work changing some parts of the code (hope it's fixed soon enough :) ).

## Contributing

There's plenty of work to do. Contact me if you want to align about the best ways of contributing to the project. But also feel free to send a Pull Request.

## License

MIT License
Copyright (c) 2016 Fabio Resner
