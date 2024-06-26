# Use the Alpine Linux base image
FROM alpine:latest

# Update the package lists and install Python and pip
RUN apk update && apk add --no-cache python3 py3-pip

# Set the working directory
WORKDIR /app

# Copy the application files to the container
COPY traffic-reproducer /app
COPY multi/run_traffic_reproducer.sh /app/

RUN mkdir /pcap

RUN chmod +x /app/run_traffic_reproducer.sh

# Install the Python dependencies
RUN pip3 install --break-system-packages --no-cache-dir -r requirements.txt

# Set the entry point command
CMD ./run_traffic_reproducer.sh


