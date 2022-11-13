#!groovy
//  groovy Jenkinsfile
properties([disableConcurrentBuilds()])

pipeline  {
    
    agent { 
        label 'master'
        }
    options {
        buildDiscarder(logRotator(numToKeepStr: '10', artifactNumToKeepStr: '10'))
        timestamps()
    }
    stages {
		stage("Removing old containers") {
            steps {
                echo 'Removing containers ...'
                 dir('.'){
                   sh ' docker ps -q --filter "name=back_dashboard" | grep -q . && docker stop back_dashboard || echo Not Found'
				
                    sh 'docker ps -q --filter "name=back_dashboard" | grep -q . && docker rm back_dashboard || echo Not Found'
                }
            }
        }
        stage("Removing old images") {
            steps {
                echo 'Removing images ...'
                 dir('.'){
                    sh 'docker ps -q --filter "name=sweetdie/back_dashboard" | grep -q . && docker rmi sweetdie/back_dashboard || echo Not Found'

                }
            }
        }
        stage("Creating images") {
            steps {
                echo 'Creating docker image ...'
                    dir('.'){
                    sh "docker build -t sweetdie/back_dashboard ."
                }
            }
        }
        stage("docker login") {
            steps {
                echo " ============== docker login =================="
                withCredentials([usernamePassword(credentialsId: 'DockerHub', usernameVariable: 'USERNAME', passwordVariable: 'PASSWORD')]) {
                    sh '''
                    docker login -u $USERNAME -p $PASSWORD
                    '''
                }
            }
        }
        stage("docker push image") {
            steps {
                echo " ============== pushing image =================="
                sh '''
                docker push sweetdie/back_dashboard:latest
                '''
            }
        }
        
        stage("docker run") {
            steps {
                echo " ============== starting backend =================="
                sh '''
                docker run -d --restart=always --name back_dashboard -p 5000:8080 sweetdie/back_dashboard:latest
                '''
            }
        }
    }
}