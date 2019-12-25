package net.gentledot.demospringsecurity.account.domain;

import lombok.*;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of =  "id")
@Builder
public class Book {

    @Id
    @GeneratedValue
    private Integer id;

    private String title;

    @ManyToOne
    private Account author;


}
