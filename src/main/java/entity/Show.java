package entity;

import jakarta.persistence.*;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalTime;

@Entity
@Table(name="show")
public class Show implements Serializable {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(nullable = false)
    private LocalDate date; // Only the date

    @Column(nullable = false)
    private LocalTime time; // Only the time

    @Column(nullable = false, length = 150)
    private String location;

    @Column(nullable = false)
    private Integer totalCapacity;

    @Column(nullable = false)
    private Integer availableTickets;

    @Column(length = 255)
    private String image; // URL or path of the event image

    // Constructors
    public Show() {}

    public Show(String name, String description, LocalDate date, LocalTime time, String location, Integer totalCapacity, Integer availableTickets, String image) {
        this.name = name;
        this.description = description;
        this.date = date;
        this.time = time;
        this.location = location;
        this.totalCapacity = totalCapacity;
        this.availableTickets = availableTickets;
        this.image = image;
    }

    // Getters and Setters
    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public LocalDate getDate() {
        return date;
    }

    public void setDate(LocalDate date) {
        this.date = date;
    }

    public LocalTime getTime() {
        return time;
    }

    public void setTime(LocalTime time) {
        this.time = time;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public Integer getTotalCapacity() {
        return totalCapacity;
    }

    public void setTotalCapacity(Integer totalCapacity) {
        this.totalCapacity = totalCapacity;
    }

    public Integer getAvailableTickets() {
        return availableTickets;
    }

    public void setAvailableTickets(Integer availableTickets) {
        this.availableTickets = availableTickets;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }

    @Override
    public String toString() {
        return "Show{" +
                "id=" + id +
                ", name='" + name + '\'' +
                ", description='" + description + '\'' +
                ", date=" + date +
                ", time=" + time +
                ", location='" + location + '\'' +
                ", totalCapacity=" + totalCapacity +
                ", availableTickets=" + availableTickets +
                ", image='" + image + '\'' +
                '}';
    }
}
