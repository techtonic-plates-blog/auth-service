# Posts service

This is the microservice for handling auth in the Thechtonic plates blog.

## How to run

To run the microservice simply compile the application with:
```bash
cargo build --release
```

And execute the binary web server at: ```target/release/auth-service```.

#### OR

Run the container, the image is located at [Containerfile](container/Containerfile).

### Necessary variables

This application is made to be run on a container, thus you need to set some environment variables for it to work, they are set at [.env](.env).