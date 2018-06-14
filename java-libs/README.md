# KBase auth

Please note that this has been superseded by auth2: http://github.com/kbase/auth2

However, these packages are still in use elsewhere, such as in `kbase/java_common`.

## Installation 

Add the following to your `build.gradle` file:

```
repositories {
    maven {
        url 'http://ci.kbase.us:8081/artifactory/gradle-dev'
    }
}

dependencies {
    implementation 'kbase:auth:0.4.4'
}
```

## Development

The source code is in `src/main/java` while the tests are in `src/test/java/`

Make sure [gradle](https://gradle.org/install/) is installed. Then run:

```sh
$ gradle wrapper
```

This generates the gradle wrapper files. Run `./gradlew build` to install dependencies, run tests, and compile. Run `./gradlew tasks` to see all available commands.

Built files live in `build/`; for example, run `./gradlew build` and check `build/libs/auth-X.Y.Z.jar`.
